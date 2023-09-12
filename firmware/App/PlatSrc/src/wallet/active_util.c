#define LOG_TAG "active_util"

#include "common.h"
#include "active_util.h"
#include "resource.h"
#include "device.h"
#include "secure_api.h"
#include "sha2.h"
#include "bignum.h"
#include "rand.h"
#include "libddi.h"
#include "base64.h"
#include "common_util.h"
#include "cmaths.h"
#include "secure_util.h"

int active_get_vnumber() {
    SHA256_CTX context;
    unsigned char sechip_id[32];
    sha256_Init(&context);
    int ret;
    ret = device_get_sn((char *) sechip_id, 24);
    if (ret <= 0) {
        db_error("get SN false ret:%d", ret);
        return -1;
    }
    sha256_Update(&context, sechip_id, ret);

    const char *cpuid = device_get_cpuid_p();
    if (strlen(cpuid) != DEVICE_CPUID_LEN) {
        db_serr("get sechip id false");
        return -1;
    }
    sha256_Update(&context, (const unsigned char *) cpuid, DEVICE_CPUID_LEN);

    ret = sechip_get_id(sechip_id);
    if (ret <= 0) {
        db_serr("get sechip id false");
        return -1;
    }
    sha256_Update(&context, sechip_id, ret);

    sha256_Final(&context, sechip_id);
    sha256_Raw(sechip_id, 32, sechip_id);
    db_msg("digest:%s", debug_ubin_to_hex(sechip_id, 32));
    unsigned int n = read_be(sechip_id);
    n = n % 1000000;
    if (!n) n = 1;
    return n;
}

int active_get_url(char *url_buffer, int len) {
    unsigned char info[64] = {0};
    int ret;
    unsigned char tmpbuf[36];
    unsigned char activekey[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    if (!url_buffer || len < 128) {
        db_serr("invalid arg");
        return -1;
    }
    XDEFINE_BUFFER(activekey);
    int version = 0x2;
    int fw_type = 1;
#ifdef BUILD_FOR_DEV
    fw_type = 0;
#endif
    int cpuid_bin_len = 4;

    unsigned char *infop = info;
    *infop++ = 'S';
    *infop++ = version | (fw_type << 4);
    write_be(infop, DEVICE_APP_INT_VERSION | (gSettings->mLang << 24));
    infop += 4;
    ret = device_get_pub_cpuid((char *) tmpbuf, sizeof(tmpbuf));
    if (ret != DEVICE_CPUID_LEN) {
        db_error("get cpuid false ret:%d", ret);
        return -2;
    }
    *infop++ = cpuid_bin_len;
    ret = hex_to_bin((const char *) tmpbuf, DEVICE_CPUID_LEN, infop, cpuid_bin_len);
    if (ret != cpuid_bin_len) {
        db_error("decode cpuid false ret:%d", ret);
        return -3;
    }
    infop += cpuid_bin_len;

    ret = device_get_sn((char *) tmpbuf, sizeof(tmpbuf));
    if (ret <= 0 || ret > 32) {
        db_error("get SN false ret:%d", ret);
        return -4;
    }
    *infop++ = ret;
    memcpy(infop, tmpbuf, ret);
    infop += ret;
    //hash
    int binlen = (int) (infop - info);
    sha256_Raw(info, binlen, tmpbuf);
    sha256_Raw(tmpbuf, 32, tmpbuf);
    memcpy(infop, tmpbuf, 2);
    infop += 2;
    binlen += 2;

    db_secure("info:%d -> %s", binlen, debug_ubin_to_hex(info, binlen));
    XDEFINE_BUFFER(activekey);
    // compute k*pub -> pub (final key)
    db_secure("seckey:%s", debug_ubin_to_hex(activekey, 32));
    ret = aes256_encrypt(info, info, binlen, activekey);
    memset(activekey, 0, 32);
    if (ret < 0) {
        db_error("encrypt info false");
        return -5;
    }
    db_secure("bin data:%d -> %s", binlen, debug_ubin_to_hex(info, binlen));
	url_buffer[0] = 'B';
    ret = 1;//snprintf(url_buffer, len, "%s%c", prefix, 'B');
    char *arg = url_buffer + ret;
    ret = Base64encode(arg, info, binlen, 0);
    Base64RefactorStr(arg, ret);
    db_info("url:%s", url_buffer);
    memset(info, 0, sizeof(info));
    memset(tmpbuf, 0, sizeof(tmpbuf));
    return strlen(url_buffer);
}

void active_init_vnum_cb(unsigned char *num) {
    int n = active_get_vnumber();
    if (n < 0) {
        return;
    }
    for (int i = 0; i < 6; i++) {
        num[i] = n % 10;
        n /= 10;
    }
}

//format: version 0x1 + len(sizeof(user_active_info)+4) + user_active_info + digest[4]
int active_decode_info(user_active_info *info, const unsigned char *data, int len) {
    unsigned char buff[sizeof(user_active_info) + 4];
    if (data[0] != 0x1 || data[1] != (sizeof(user_active_info) + 4) || len < data[1] + 2) {
        db_serr("invalid head:%s", debug_ubin_to_hex(data, 4));
        return -1;
    }
    data += 2;
    len -= 2;
    unsigned char seckey[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };

    XDEFINE_BUFFER(seckey);
    //db_secure("data %d:%s", len, debug_ubin_to_hex(data, len));
    if (aes256_decrypt(data, buff, sizeof(user_active_info) + 4, seckey) != 0) {
        memset(seckey, 0, sizeof(seckey));
        db_serr("decrypt false");
        return -1;
    }
    memset(seckey, 0, sizeof(seckey));

    db_secure("buff:%s", debug_ubin_to_hex(buff, sizeof(buff)));
    sha256_Raw(buff, sizeof(user_active_info), info->sign_data);//tmp use as buffer
    if (memcmp(info->sign_data, buff + sizeof(user_active_info), 4) != 0) {
        db_serr("invalid digest");
        return -1;
    }
    user_active_info *d = (user_active_info *) buff;
    if (d->tag[0] != 'U' || d->tag[1] != 'A') {
        db_serr("invalid tag");
        return -1;
    }
    if (d->version != 0x1) {
        db_serr("invalid version:%d", d->version);
        return -1;
    }
    int mini_sign_index = 1;
#ifdef BUILD_FOR_RELEASE
    mini_sign_index = 2;
#endif
    if (d->sign_index < mini_sign_index) {
        db_serr("invalid sign_index:%d < %d", d->version, mini_sign_index);
        return -1;
    }
    if (device_check_sn(d->sn) != 0) {
        db_serr("invalid sn");
        return -1;
    }
    d->time = ntohl(d->time);
    if (d->time < 1564617600) {    //UTC 2019-08-01
        db_serr("invalid time:%u", d->time);
        return -1;
    }
    d->time_zone = ntohl(d->time_zone);
    if (d->time_zone<-(15 * 3600) || d->time_zone>(15 * 3600)) {
        db_serr("invalid time_zone:%d", d->time_zone);
        return -1;
    }
    if (buffer_is_zero(d->sign_data, sizeof(d->sign_data))) {
        db_serr("invalid sign_data");
        return -1;
    }
	db_msg("d->time:%d, d->time_zone:%d", d->time, d->time_zone);
    memcpy(info, d, sizeof(user_active_info));
    return 0;
}
