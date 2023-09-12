#define LOG_TAG "app_sapi"

#include <stdio.h>
#include <string.h>
#include "secure_api.h"
#include "debug.h"
#include "platform.h"
#include "rand.h"
#include "bignum.h"
#include "secp256k1.h"
#include "sha2.h"
#include "xstr.h"
#include "loading_win.h"
#include "settings.h"
#include "device.h"
#include "coin_util.h"
#include "global.h"
#include "wallet_util.h"
#include "bip32.h"
#include "bip39.h"
#include "libddi.h"
#include "common_util.h"
#include "secure_util.h"

#define GET_UINT_FROM_BBUF(buf)            \
    (uint32_t)(                              \
        ((((uint8_t *)(buf))[3]) << 0)    |        \
        ((((uint8_t *)(buf))[2]) << 8)    |        \
        ((((uint8_t *)(buf))[1]) << 16)    |        \
        ((((uint8_t *)(buf))[0]) << 24))

#define GET_USHORT_FROM_BBUF(buf)            \
    (uint16_t)(                                    \
        ((((uint8_t *)(buf))[1]) << 0)    |        \
        ((((uint8_t *)(buf))[0]) << 8))

enum {
    SAPI_CMD_HANDSHAKE0 = 0x1,
    SAPI_CMD_HANDSHAKE1 = 0x2,

    SAPI_CMD_GET_BASE_INFO = 0x11,
    SAPI_CMD_GET_XPUB = 0x12,
    SAPI_CMD_SIGN_DIGEST = 0x13,
    SAPI_CMD_GET_RANDOM = 0x14,
    SAPI_CMD_CHANGE_PASSWD = 0x15,
    SAPI_CMD_GET_STATE_INFO = 0x16,
    SAPI_CMD_CHECK_PASSWD = 0x17,

    SAPI_CMD_STORE_SEED = 0xA1,
    SAPI_CMD_DESTORY_SEED = 0xA2,
    SAPI_CMD_VERIFY_MNEMONIC = 0xA5,
    SAPI_CMD_SET_PASSPHRASE = 0xA6,
    SAPI_CMD_ENCODE_DATA = 0xA9,
    SAPI_CMD_DECODE_DATA = 0xAA,

};

int sapi_subcode = 0;

static unsigned char iobuff[264] = {0};
static char unit_inited = 0;
static unsigned int se_app_version = 0;
static int handshake_state = 0;
static unsigned char handshake_code[16] = {0};

static int G_lock = 0;

static inline void
LOCK() {
    //while (__sync_lock_test_and_set(&(G_lock), 1)) {}
}

static inline void
UNLOCK() {
    //__sync_lock_release(&(G_lock));
}

static inline int ser_uint16(unsigned char *buf, uint16_t n) {
    buf[1] = (unsigned char) n;
    buf[0] = (unsigned char) (n >> 8);
    return sizeof(uint16_t);
}

static inline int ser_uint32(unsigned char *buf, uint32_t n) {
    buf[3] = (unsigned char) n;
    buf[2] = (unsigned char) (n >> 8);
    buf[1] = (unsigned char) (n >> 16);
    buf[0] = (unsigned char) (n >> 24);
    return sizeof(uint32_t);
}

static inline int ser_data(unsigned char *buf, const unsigned char *data, unsigned char l) {
    buf[0] = l;
    memcpy(buf + 1, data, l);
    return l + 1;
}

static inline int check_passhash_len(int len) {
    return (len == 32);
}

static int call_secure_agent_l(int cmd, const unsigned char *data, int size, unsigned char *out, unsigned int outsize, int mini_expect_size) {
    int ret = -1;
    unsigned char *p;
    sapi_subcode = 0;
    if (!unit_inited && cmd > 0xF) {
        db_serr("not inited cmd:0x%x", cmd);
        return -1;
    }
    if (size > 0xF0) {
        db_serr("invalid len:%d cmd:0x%x", size, cmd);
        return -1;
    }
    if (!handshake_state && cmd > 0xF && cmd < 0xE0) {
        db_serr("invalid handshake state:%d cmd:0x%x", handshake_state, cmd);
        return -1;
    }
    int iolen = 0;
    memset(iobuff, 0, sizeof(iobuff));
    if (data && size > 0) {
        memcpy(iobuff + iolen, data, size);
        iolen += size;
    }

    db_secure("sapi cmd:0x%x req:%d -> %s", cmd, iolen, debug_ubin_to_hex(iobuff, iolen));
    ret = sec_sapi_command(cmd, iolen, iobuff, iobuff);
    if (ret < 0) {
        db_serr("sapi cmd:%#x ret:%d code:0x%x", cmd, ret, iobuff[1]);
        size = 4;
        if (iobuff[1] == 0) iobuff[1] = 0xF0; //sapi error?
    } else {
        size = ret;
    }

    db_secure("sapi cmd:0x%x resp:%d -> %s", cmd, ret, debug_ubin_to_hex(iobuff, size));
    if (iobuff[0] != cmd) {
        db_serr("invalid respone cmd:0x%x resp:%s", cmd, debug_ubin_to_hex(iobuff, size));
        return -5;
    }
    if (iobuff[1] != 0) {
        db_serr("invalid result cmd:0x%x code:0x%x subcode:0x%x %x resp:%s", cmd, iobuff[1], iobuff[2], iobuff[3], debug_ubin_to_hex(iobuff, size));
        ret = iobuff[1];
        if (ret > 0) ret = -ret;
        sapi_subcode = iobuff[2] | (iobuff[3] << 8);
        return ret;
    }

    if (out) {
        p = iobuff + 4;
        size -= 4;
        if ((int) outsize < size) {
            db_serr("buffer size:%d < dataszie:%d", outsize, size);
            size = outsize;
        }
        if (size > 0) {
            memcpy(out, p, size);
        }
        if (mini_expect_size > 0 && size < mini_expect_size) { //no resp data
            db_serr("resp size:%d < mini_expect_size:%d", size, mini_expect_size);
            return -10;
        } else {
            return size;
        }
    } else {
        return 0;
    }
}

static int call_secure_agent(int cmd, const unsigned char *data, int size, unsigned char *out, unsigned int outsize, int mini_expect_size) {
    LOCK();
    int ret = call_secure_agent_l(cmd, data, size, out, outsize, mini_expect_size);
    UNLOCK();
    return ret;
}

static int call_secure_agent0(int cmd, const unsigned char *data, int size) {
    LOCK();
    int ret = call_secure_agent_l(cmd, data, size, NULL, 0, 0);
    UNLOCK();
    return ret;
}

static void reset_all_state() {
    db_secure("current inited:%d handshake:%d", unit_inited, handshake_state);
    unit_inited = 0;
    handshake_state = 0;
    memset(handshake_code, 0, sizeof(handshake_code));
    memset(iobuff, 0, sizeof(iobuff));
    gSeedAccountId = 0;
}

static void set_se_waittime(uint16_t curv, int time) {
}

static void clean_se_waittime() {
}

static void build_handshake_version(unsigned int se_version, int app_version, unsigned char buff[8], const unsigned char perdata[32]) {
    write_be(buff, se_version);
    write_be(buff + 4, app_version);
    //ALOGD("perdata:%s", debug_bin_to_hex(perdata, 32));
    //ALOGD("buff raw:%s", debug_bin_to_hex(buff, 8));
    unsigned char p = 7;

    int buffer_len = 32;
    for (int i = (buffer_len - 1); i >= 0; i--) {
        buff[p % 8] ^= perdata[i];
        --p;
        //ALOGD("r%d :%s", i, debug_bin_to_hex(buff, 8));
    }
}

// HANDSHAKE0
// version 2:
// inbuf:   client curve_point(32byte x| 32byte y) | random(32byte)
// outbuf:  secure curve_point(32byte x| 32byte y) | resp digest(16byte) | random(32byte) | 1 device type | 4 app version| 1 flag | 64byte signdata
// HANDSHAKE1
// inbuf: resp digest(16byte)
// outbuf: save as sapi_get_base_info
static int sapi_handshake() {
    db_secure("handshake start");
    unsigned char buffer[256];
    unsigned char randnum[32];
    unsigned char se_randnum[32];
    unsigned char *p;
    const ecdsa_curve *curve = &secp256k1;
    bignum256 k;
    curve_point pub;
    handshake_state = 0;
    memset(buffer, 0, sizeof(buffer));
    do {
        random_buffer(buffer, 32);
        db_secure("myrandkey:%s", debug_ubin_to_hex(buffer, 32));
        bn_read_be(buffer, &k);
    } while (bn_is_zero(&k) || !bn_is_less(&k, &curve->order));

    point_multiply(curve, &k, &curve->G, &pub);
    bn_write_be(&pub.x, buffer + 0);
    bn_write_be(&pub.y, buffer + 32);
    db_secure("my pubkey:%s", debug_ubin_to_hex(buffer, 64));
    random_buffer(randnum, 32);
    db_secure("randnum:%s", debug_ubin_to_hex(randnum, 32));
    memcpy(buffer + 64, randnum, 32);

    int h0_version;
    int have_sign_resp = 0;
    int ret = call_secure_agent(SAPI_CMD_HANDSHAKE0, buffer, 96, buffer, sizeof(buffer), 89);
    if (ret < 0) {
        db_serr("HANDSHAKE0 ret:%d", ret);
        if (ret < 0) {
            return ret;
        }
    }
    if (ret == 118 || ret == (118 + 64)) {
        h0_version = 2;
        if (ret == (118 + 64)) have_sign_resp = 1;
    } else {
        db_serr("invalid ret:%d", ret);
        return -1;
    }

    //check resp
    bn_read_be(buffer + 0, &pub.x);
    bn_read_be(buffer + 32, &pub.y);
    if (!ecdsa_validate_pubkey(curve, &pub)) {
        db_serr("invalid resp pubkey inbuf:%s", debug_ubin_to_hex(buffer, 64));
        return -2;
    }
    p = buffer + 64;
    //check digest
    unsigned char salt[] = {
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    };
    XDEFINE_BUFFER(salt);
    sha256_message(salt, sizeof(salt), randnum, 4, buffer); //reuse buffer save digest
    memset(salt, 0, sizeof(salt));
    if (memcmp(buffer, p, 16) != 0) {
        db_serr("invalid resp digest expect:%s", debug_ubin_to_hex(buffer, 16));
        db_serr("digest resp:%s", debug_ubin_to_hex(p, 16));
        return -3;
    }
    p += 16;
    if (h0_version == 2) {
        memcpy(se_randnum, p, 32); //tmp save
        p += 32;
    }

    unsigned int device_type = *p++;
    unsigned int app_version = GET_UINT_FROM_BBUF(p);
    unsigned char flag = 0;
    if (device_type != SECHIP_DEVICE_TYPE) {
        db_serr("invalid device_type:%d != need:%d", device_type, SECHIP_DEVICE_TYPE);
        return -4;
    }
    if (h0_version == 2) {
        p += 4;
        flag = *p++;
    }
    se_app_version = app_version;
    db_secure("HANDSHAKE0 version:%d resp device_type:%d app_version:%d flag:0x%02x sign:%d", h0_version, device_type, app_version, flag, have_sign_resp);
    if (!have_sign_resp && device_is_inited()) {
        db_serr("device inited,but not sign resp");
        return -11;
    }
    if (have_sign_resp) {
        if (device_check_se_shake(randnum, p) != 0) {
            db_serr("check shake sign false");
            return -5;
        }
    }
    int hs1_len = 16;
    if (flag & 0x1) {
        //reuse buffer in handshake1
        if (device_sign_se_shake(se_randnum, buffer + 16) != 0) {
            db_serr("sign shake false");
            return -5;
        }
        hs1_len += 64;
    }

    unsigned char salt_h[] = {
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
	};
    XDEFINE_BUFFER(salt_h);
    sha256_message(salt_h, sizeof(salt_h), se_randnum, 4, se_randnum);
    memset(salt_h, 0, sizeof(salt_h));
    memcpy(buffer, se_randnum, 16);

    if (flag & 0x2) { //resp client app version
        build_handshake_version(se_app_version, DEVICE_APP_INT_VERSION, buffer + hs1_len, buffer);
        hs1_len += 8;
    }

    ret = call_secure_agent0(SAPI_CMD_HANDSHAKE1, buffer, hs1_len);
    if (ret < 0) {
        db_serr("HANDSHAKE1 ret:%d", ret);
        return ret;
    }
    //save handshake code
    point_multiply(curve, &k, &pub, &pub);
    bn_write_be(&pub.x, buffer);
    bn_write_be(&pub.y, buffer + 32);
    sha256_Raw(buffer, 64, buffer);
    memcpy(handshake_code, buffer, 16);
    handshake_state = 1;
    db_secure("handshake end,code:%s", debug_ubin_to_hex(handshake_code, 16));
    return 0;
}

int sechip_get_id(unsigned char id[SECHIP_EXT_ID_LEN]) {
    uint8_t digest[32] = {0};
    if (sec_read_chipid(digest) != 0) {
        return -1;
    }
    memcpy(id, digest, SECHIP_EXT_ID_LEN);
    memzero(digest, sizeof(digest));
    return SECHIP_EXT_ID_LEN;
}

int sechip_get_hostkey(unsigned char hostkey[16]) {
    uint8_t digest[32] = {0};
    if (sec_read_chipid(digest) != 0) {
        return -1;
    }
    sha256_Raw(digest, 16, digest);
    memcpy(hostkey, digest, 16);
    memzero(digest, sizeof(digest));
    return 16;
}

int sapi_reset() {
    LOCK();
    reset_all_state();
    UNLOCK();
    return 0;
}

int sapi_init() {
    int ret;
    db_secure("start inited:%d", unit_inited);
    if (unit_inited) {
        return 0;
    }
    LOCK();
    if (unit_inited) {
        db_secure("unit_inited skip...");
        return 0;
    }
    reset_all_state();
    unit_inited = 1;
    UNLOCK();

    unsigned char id[SECHIP_EXT_ID_LEN] = {0};
    ret = sechip_get_id(id);
    if (ret <= 0) {
        unit_inited = 0;
        db_serr("get chipid false ret:%d", ret);
        return -23;
    }
    db_secure("chipid:%s", debug_ubin_to_hex(id, SECHIP_EXT_ID_LEN));

    ret = sapi_handshake();
    if (ret != 0) {
        unit_inited = 0;
        db_serr("handshake false ret:%d", ret);
        return ret;
    }
    db_secure("end");
    return 0;
}

void sapi_destory() {
    reset_all_state();
}

//inbuf: none
//outbuf 1 device type |  4 app version | lv 1+8  chipid | 1 max passwd error times
int sapi_get_base_info(sec_base_info *info) {
    memset(info, 0, sizeof(sec_base_info));
    unsigned char resp[32] = {0};
    int ret = call_secure_agent(SAPI_CMD_GET_BASE_INFO, NULL, 0, resp, sizeof(resp), 14);
    if (ret < 0) {
        db_serr("get base info false,ret:%d", ret);
        return ret;
    }
    unsigned char *p = resp;
    info->chip_type = *p++;
    info->app_version = GET_UINT_FROM_BBUF(p);
    p += 4;
    info->chipid_len = *p++;
    if (info->chipid_len > SCHIP_CHIPID_SIZE) info->chipid_len = SCHIP_CHIPID_SIZE;
    memcpy(info->chipid, p, info->chipid_len);
    p += info->chipid_len;
    info->max_passwd_error_times = *p;
    db_secure("chip:%d app version:%d chipid:%s max_passwd_error_times:%d", info->chip_type, info->app_version,
              debug_ubin_to_hex(info->chipid, info->chipid_len), info->max_passwd_error_times);
    if (info->max_passwd_error_times == 0) info->max_passwd_error_times = 5;
    return 0;
}

//outbuf: 1 seed state |  2 set_seed_times | 1 passwd_error_times | 8 seed account id | 1 mnemonic
int sapi_get_state_info(sec_state_info *info) {
    memset(info, 0, sizeof(*info));
    unsigned char resp[16] = {0};
    int ret = call_secure_agent(SAPI_CMD_GET_STATE_INFO, NULL, 0, resp, sizeof(resp), 4);
    if (ret < 0) {
        db_serr("get state info false,ret:%d", ret);
        return ret;
    }
    unsigned char *p = resp;
    info->seed_state = *p++;
    info->set_seed_times = GET_USHORT_FROM_BBUF(p);
    p += 2;
    info->passwd_error_times = *p++;
    if (ret >= 12) { //account id
        if (buffer_is_zero(p + 4, 4)) { //is zero
            *(p + 7) = 0;
        }
        info->account_id = read_be64(p);
        p += 8;
    }
    if (ret >= 13) { //account id
        info->mnemonic = *p++;
    }
    if (info->seed_state == 1) {
        if (!info->account_id) {
            info->account_id = 1;
        }
    } else {
        info->account_id = 0;
    }
    gSeedAccountId = info->account_id; //auto update

    db_secure("seed state:%d times:%d passwd error:%d account:%llx mnemonic:%d",
              info->seed_state, info->set_seed_times, info->passwd_error_times, info->account_id, info->mnemonic);
    return 0;
}

uint64_t sapi_get_account_id() {
    sec_state_info info;
    memset(&info, 0, sizeof(sec_state_info));
    int ret = sapi_get_state_info(&info);
    if (ret != 0 || info.seed_state != 1) {
        return 0;
    }
    return info.account_id;
}

// inbuf: len(u8)
// outbuf: input len
int sapi_get_random(unsigned char *buff, int size) {
    int ret = -1;
    int checksize = size > 8 ? 8 : size;
    int times = 0;
    unsigned char req[1];
    if (size < 1 || size > 128) {
        db_serr("invalid size:%d", size);
        return -1;
    }
    for (times = 0; times < 3; times++) {
        req[0] = (unsigned char) size;
        memset(buff, 0, checksize);
        ret = call_secure_agent(SAPI_CMD_GET_RANDOM, req, 1, buff, size, size);
        if (ret < 0) {
            db_serr("get random false,ret:%d", ret);
            return ret;
        }
        if (ret != size) {
            db_serr("invalid random ret:%d", ret);
            return -1;
        }
        if (buffer_is_zero(buff, checksize)) {
            ret = -1;
            db_serr("invalid random zero result len:%d times:%d", checksize, times);
            continue;
        }
        db_secure("radom size:%d data:%s", size, debug_ubin_to_hex(buff, size));
        break;
    }
    return (ret == size) ? size : -1;
}

static int is_se_builtin_curve(uint16_t curv) {
    return (curv == CURVE_SECP256K1 || curv == CURVE_NIST256P1) ? 1 : 0;
}


// inbuf: passwd(lv) | 1 encode type | data(lv) | 8byte digest
// outbuf: encoded_data(lv)
int sapi_encode_data(const unsigned char *passwd, int passlen, uint8_t encode_type, const unsigned char *data, int len, unsigned char *encode_data, int size) {
    unsigned char buf[176] = {0};
    int ret;
    if (!check_passhash_len(passlen)) {
        db_serr("invaild passlen:%d", passlen);
        return -1;
    }
    if (len < 1 || len > 128) {
        db_serr("invaild data len:%d", len);
        return -1;
    }
    sha256_Raw(data, len, buf);

    memcpy(buf + passlen + len + 3, buf, 8);//copy digest

    unsigned char *p = buf;
    p += ser_data(p, (const unsigned char *) passwd, passlen);
    *p++ = encode_type;
    p += ser_data(p, (const unsigned char *) data, len);
    p += 8;

    ret = call_secure_agent(SAPI_CMD_ENCODE_DATA, buf, p - buf, buf, sizeof(buf), len + 21);
    if (ret < 0) {
        db_serr("encde data false ret:%d", ret);
        memzero(buf, sizeof(buf));
        return ret;
    }
    if (*buf + 1 != ret) {
        db_serr("invalid ret:%d total len:%d", ret, *buf);
        memzero(buf, sizeof(buf));
        return -0x41;
    }
    if (size < ret) {
        db_serr("buff size:%d < data len:%d", size, ret);
        memzero(buf, sizeof(buf));
        return -0x42;
    }
    memcpy(encode_data, buf, ret);
    if (ret < size) encode_data[ret] = 0;
    memzero(buf, sizeof(buf));
    return ret;
}


// inbuf: curv(2byte) | passwd(lv) | path(lv)
// outbuf: depth(1) | child_num(4) | chain_code(32) | public_key(33) | FINGERPRINT(32)
int sapi_get_xpub(uint16_t curv, const char *path, const unsigned char *passwd, int passlen, unsigned char *xpub, unsigned int size) {
    unsigned char buf[80] = {0};
    int ret;
    int pathlen = strlen(path);
    if (!path || pathlen < 5) {
        db_serr("invaild patch:%s", path);
        return -1;
    }
    if (!check_passhash_len(passlen)) {
        db_serr("invaild passlen:%d", passlen);
        return -1;
    }
    if (size < 102) {
        db_serr("invalid size:%d", size);
        return -1;
    }
    db_secure("curv:%d path:%s", curv, path);

    if (!is_se_builtin_curve(curv)) {
        return -1;
    }
    unsigned char *p = buf;
    p += ser_uint16(p, curv);
    p += ser_data(p, (const unsigned char *) passwd, passlen);
    p += ser_data(p, (const unsigned char *) path, pathlen);
    set_se_waittime(curv, 3000);
    ret = call_secure_agent(SAPI_CMD_GET_XPUB, buf, p - buf, xpub, size, 102);
    clean_se_waittime();
    return ret;
}

// inbuf: curv(2byte) | passwd(lv) | path(lv) | data(lv) | check_func_id
// outbuf: r(32byte) + s(32byte) + by(1byte)
int sapi_sign_digest(uint16_t curv, const char *path, const unsigned char *passhash, unsigned char sz_passhash,
                     const unsigned char *data, unsigned int size, unsigned char check_func, unsigned char *out, unsigned int outsize) {
    unsigned char buf[128];
    int pathlen = strlen(path);
    if (!check_passhash_len(sz_passhash)) {
        db_serr("invalid passhash len:%d", sz_passhash);
        return -1;
    }
    db_secure("curv:%d path:%s", curv, path);
    if (!is_se_builtin_curve(curv)) {
        return -1;
    }
    if (size != 32) {
        db_serr("invalid digest len:%d", size);
        return -1;
    }
    if (sizeof(curv) + pathlen + size + sz_passhash >= sizeof(buf)) {
        db_serr("buffer overload path:%s size:%d", path, size);
        return -1;
    }

    unsigned char *p = buf;
    p += ser_uint16(p, curv);
    p += ser_data(p, passhash, sz_passhash);
    p += ser_data(p, (const unsigned char *) path, pathlen);
    p += ser_data(p, data, size);
    *p++ = check_func;

    set_se_waittime(curv, 5000);
    int ret = call_secure_agent(SAPI_CMD_SIGN_DIGEST, buf, p - buf, out, outsize, 65);
    clean_se_waittime();
    return ret;
}

// inbuf: old passwd(lv) | new passwd(lv)
int sapi_change_passwd(const unsigned char *oldpasswd, int oldlen, const unsigned char *newpasswd, int newlen) {
    unsigned char buf[68];
    if (!check_passhash_len(oldlen) || !check_passhash_len(newlen)) {
        db_serr("invaild len old:%d new:%d", oldlen, newlen);
        return -1;
    }
    unsigned char *p = buf;
    *p++ = (unsigned char) oldlen;
    memcpy(p, oldpasswd, oldlen);
    p += oldlen;
    *p++ = (unsigned char) newlen;
    memcpy(p, newpasswd, newlen);

    int ret = call_secure_agent0(SAPI_CMD_CHANGE_PASSWD, buf, oldlen + newlen + 2);
    if (ret != 0) {
        db_serr("change passwd false ret:%d", ret);
    }
    return ret;
}

// inbuf: old passwd(lv)
int sapi_check_passwd(const unsigned char *oldpasswd, int oldlen) {
    unsigned char buf[36];
    /*if (se_app_version >= 10001 && se_app_version <= 10008) {
        db_secure("auto change passhash len to 16");
        oldlen = 16;
    }*/
    if (!check_passhash_len(oldlen)) {
        db_serr("invaild len passwd:%d", oldlen);
        return -1;
    }
    unsigned char *p = buf;
    *p++ = (unsigned char) oldlen;
    memcpy(p, oldpasswd, oldlen);

    int ret = call_secure_agent0(SAPI_CMD_CHECK_PASSWD, buf, oldlen + 1);
    if (ret != 0) {
        db_serr("check passwd false ret:%d", ret);
    }
    return ret;
}

// inbuf: seed(lv) | passwd(lv) | 8 byte digest
int sapi_store_seed(const unsigned char *seed, int seedlen, const unsigned char *passwd, int passlen) {
    unsigned char buf[128];
    if (!check_passhash_len(passlen)) {
        db_serr("invaild passlen:%d", passlen);
        return -1;
    }
    if (seedlen < 64 || seedlen > 80) {
        db_serr("invaild seedlen:%d", seedlen);
        return -1;
    }
    gSeedAccountId = 0;
    unsigned char *p = buf;
    *p++ = (unsigned char) seedlen;
    memcpy(p, seed, seedlen);
    p += seedlen;
    *p++ = (unsigned char) passlen;
    memcpy(p, passwd, passlen);
    p += passlen;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    sha256_message(seed, seedlen, passwd, passlen, digest);
    memcpy(p, digest, 8);

    int ret = call_secure_agent0(SAPI_CMD_STORE_SEED, buf, seedlen + passlen + 2 + 8);
    if (ret != 0) {
        db_serr("store seed false ret:%d", ret);
    }
    return ret;
}

int sapi_destory_seed() {
    gSeedAccountId = 0;
    return call_secure_agent0(SAPI_CMD_DESTORY_SEED, NULL, 0);
}

// inbuf: passwd(lv) | mnemonic(lv) | 8 mnemonic digest
int sapi_verify_mnemonic(const unsigned char *passwd, int passlen, const unsigned char *mnemonic, int len) {
    unsigned char buf[200];
    if (!check_passhash_len(passlen)) {
        db_serr("invaild passlen:%d", passlen);
        return -1;
    }
    if (*(mnemonic + len)) {
        db_serr("invaild mnemonic non end 0");
        return -2;
    }
    unsigned char *p = buf;
    *p++ = (unsigned char) passlen;
    memcpy(p, passwd, passlen);
    p += passlen;
    if (len > 128) {
        *p++ = 64;
        sha512_Raw(mnemonic, len, p);
        p += 64;
        sha256_Raw(p - 64, 64, p);
    } else {
        *p++ = len;
        memcpy(p, mnemonic, len);
        p += len;
        sha256_Raw(mnemonic, len, p);
    }
    p += 8;
    set_se_waittime(0, 4000);
    int ret = call_secure_agent0(SAPI_CMD_VERIFY_MNEMONIC, buf, p - buf);
    clean_se_waittime();
    if (ret != 0) {
        db_serr("verify mnemonic false ret:%d", ret);
        return ret;
    }
    return 0;
}

// // inbuf: passwd(lv) | passphrase(lv)| passphrase digest 8
int sapi_set_passphrase(const unsigned char *passwd, int passlen, const unsigned char *data, int len) {
    unsigned char buf[128];
    if (!check_passhash_len(passlen)) {
        db_serr("invaild passlen:%d", passlen);
        return -1;
    }
    if (len > 60) {
        db_serr("invaild passphrase len:%d", len);
        return -2;
    }
    gSeedAccountId = 0;
    unsigned char *p = buf;
    *p++ = (unsigned char) passlen;
    memcpy(p, passwd, passlen);
    p += passlen;
    *p++ = len;
    memcpy(p, data, len);
    p += len;
    sha256_Raw(data, len, p);
    p += 8;
    set_se_waittime(0, 4000);
    int ret = call_secure_agent0(SAPI_CMD_SET_PASSPHRASE, buf, p - buf);
    clean_se_waittime();
    if (ret != 0) {
        db_serr("set passphrase false ret:%d", ret);
    }
    return ret;
}
