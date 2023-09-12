#define LOG_TAG "device"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "common_c.h"
#include "device.h"
#include "sha2.h"
#include "libddi.h"
#include "crypto/secp256k1.h"
#include "secure_util.h"
#include "secure_api.h"
#include "global.h"
#include "update.h"
#include "secp256k1.h"
#include "cmaths.h"
#include "common_util.h"

#define PRIVATE_DATA_VERSION_V1 0x1
#define PRIVATE_DATA_VERSION 0x2
#define PRIVATE_DATA_PACK_VERSION 0x2
#define PRIVATE_DATA_BAKUP_OFFSET   0x1000
#define NVM_HEADER_LEN  4
#define NVM_ADDR_BASE 0x400

//private+nvm 8k
//private(1k) + nvm(3k) | backup:private(1k) + nvm(3k)
#define PRIVATE_DATA_BASE_AREA           INTERNAL_PRIVATE_DATA_ADDR
#define PRIVATE_DATA_BASE_MAXSIZE        (4*1024UL)
#define PRIVATE_DATA_BACKUP_AREA         (PRIVATE_DATA_BASE_AREA+PRIVATE_DATA_BASE_MAXSIZE)
#define PRIVATE_DATA_BACKUP_MAXSIZE      (4*1024UL)

//PRIVATE_DATA_BASE_AREA
//  user active(128) |  settings (128) | seed info(32)
#define NVM_ADDR_USER_ACTIVE_OFFSET (NVM_ADDR_BASE + 0)
#define NVM_ADDR_SETTINGS_OFFSET    (NVM_ADDR_BASE + 128)
#define NVM_ADDR_SEED_INFO_OFFSET   (NVM_ADDR_BASE + 128 + 128)

#define FILE_HASH_SIZE 20

#define PRIVATE_TAG_LEN 4
#define PRIVATE_SN_LEN 23
#define PRIVATE_SN_SIZEOF 24

#define DEVICE_ID_SIZEOF 20

#define HOSTKEY_SIZEOF 20

#define BOOT0_TOTAL_SIZE 0x8000
#define BOOT0_SIGN_SIZE 128
#define BOOT0_PRIVATE_DATA_SIZE 320
#define BOOT0_PRIVATE_DATA_OFFSET (BOOT0_TOTAL_SIZE - 1024 + BOOT0_SIGN_SIZE)

#define DEVICE_CPUID_BUFFSIZE (DEVICE_CPUID_LEN+4)

typedef struct {
    char check[PRIVATE_TAG_LEN];
    int16_t version;
    uint16_t len;
    char sn[PRIVATE_SN_SIZEOF];
    char id[24];
    char hostkey[20];
    unsigned char host_privkey[32];
    unsigned char se_type;
    unsigned char se_hostkey[16];
    unsigned char se_pubkey[33];
    char inited;
    unsigned char sign_index;
    unsigned char sign_data[64];
} PrivateDataInfo;

typedef struct {
    char check[PRIVATE_TAG_LEN];
    int16_t version;
    uint16_t payload_len;
    unsigned char header_len;
    char reserve[2];
    unsigned char digest[32];
} PrivateDataPacker;

typedef struct {
    unsigned char tag[4];
    unsigned char digest[32];
    unsigned char signdata[64];
} sign_data_t;

typedef struct {
    uint64_t id;
    unsigned char _r[16];
} seed_info_t;

static char gPrivateTag[PRIVATE_TAG_LEN] = {'A', 'B', 'C', 'D'};
static char gPrivatePackTag[PRIVATE_TAG_LEN] = {'A', 'B', 'C', 'D'};
static unsigned char gAESKeyMark[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static char g_CpuId[DEVICE_CPUID_BUFFSIZE] = {0};
static PrivateDataInfo gPrivateData[1] = {0};
static int gPrivDataCached = 0;

static int gValidRomResult = 0;
static int gActiveTime = -1;

static int clearNvmData(int addr, int size, int block) {
    unsigned char tmp[256];
    if (size < 1 || size > 0xFF) {
        db_serr("%d invalid input param", __LINE__);
        return -1;
    }
    if (size < NVM_HEADER_LEN) size = NVM_HEADER_LEN;

    int area = PRIVATE_DATA_BASE_AREA + block * PRIVATE_DATA_BAKUP_OFFSET;
    memset(tmp, 0xFF, size);
    int ret = ddi_flash_write(area + addr, tmp, size);
    if (ret != size) {
        db_serr("write nvm addr:0x%x block:%d header false ret:%d", addr, block, ret);
        return -3;
    }
    if (block == 0) { //backup
        clearNvmData(addr, size, 1);
    }
    return size;
}

static int writeNvmData(int addr, const void *data, int size, int block, int backup) {
    unsigned char tmp[NVM_HEADER_LEN + 0xFF];
    int ret = -1;

    if (NULL == data || size < 1 || size > 0xFF) {
        db_serr("%d invalid input param", __LINE__);
        return -1;
    }

    int area = PRIVATE_DATA_BASE_AREA + block * PRIVATE_DATA_BAKUP_OFFSET;
    tmp[0] = 0xca;
    tmp[1] = 0x48;
    tmp[2] = 0;
    tmp[3] = size & 0xFF;
    memcpy(tmp + NVM_HEADER_LEN, data, size);
    ret = ddi_flash_write(area + addr, tmp, NVM_HEADER_LEN + size);
    if (ret != (NVM_HEADER_LEN + size)) {
        db_serr("write nvm addr:0x%x block:%d header false ret:%d", addr, block, ret);
        return -3;
    }
    if (block == 0 && backup) { //backup
        writeNvmData(addr, data, size, 1, 0);
    }
    return size;
}

static int readNvmData(int addr, void *data, int size, int block) {
    unsigned char tmp[NVM_HEADER_LEN] = {0};
    if (NULL == data || size < 1) {
        db_serr("invalid input param");
        return -1;
    }

    int area = PRIVATE_DATA_BASE_AREA + block * PRIVATE_DATA_BAKUP_OFFSET;
    int ret = ddi_flash_read(area + addr, tmp, NVM_HEADER_LEN);
    if (ret != NVM_HEADER_LEN || tmp[0] != 0xca || tmp[1] != 0x48 || tmp[2] != 0) {
        db_serr("invalid nvm:%d header block:%d", addr, block);
        if (block == 0) {
            return readNvmData(addr, data, size, 1);
        } else {
            return -3;
        }
    }
    int readlen = (size > tmp[3]) ? tmp[3] : size;
    ret = ddi_flash_read(area + addr + NVM_HEADER_LEN, data, readlen);
    if (ret != readlen) {
        db_secure("read data ret:%d != %d ", ret, readlen);
        return -4;
    }
    return readlen;
}

static void initPrivateData(PrivateDataInfo *privdata) {
    memset(privdata, 0, sizeof(PrivateDataInfo));
    memcpy(privdata->check, gPrivateTag, PRIVATE_TAG_LEN);
    privdata->version = PRIVATE_DATA_VERSION;
    privdata->len = sizeof(PrivateDataInfo) - 6;
}

static int getPrivateAESKey(unsigned char *key) {
    SHA256_CTX context;
    sha256_Init(&context);
    unsigned char buff[32] = {0};
    XDEFINE_BUFFER2(buff, 32, gAESKeyMark);
    //db_secure("buff:%s", debug_ubin_to_hex(buff, 32));
    sha256_Update(&context, buff, 32);
    sha256_Update(&context, (uint8_t *) PRODUCT_TYPE_VALUE, strlen(PRODUCT_TYPE_VALUE));
    const char *cpuid = device_get_cpuid_p();
    if (strlen(cpuid) != DEVICE_CPUID_LEN) {
        db_serr("get sechip id false");
        return -1;
    }
    sha256_Update(&context, (unsigned char *) cpuid, DEVICE_CPUID_LEN);
    memset(buff, 0, sizeof(buff));
    sha256_Final(&context, key);
    return 32;
}

static int writeEncryptNvmData(int addr, const void *data, int size, int block, int backup) {
    unsigned char buff[256];
    if (size < 1 || size > 250) {
        db_error("invalid size:%d", size);
        return -1;
    }
    unsigned char key[32];
    sha256_Raw(data, size, key);
    memcpy(buff, data, size);
    memcpy(buff + size, key, 4);
    int total_len = size + 4;
    if (getPrivateAESKey(key) != 32) {
        db_serr("get AES key false");
        return -1;
    }
    int ret = aes256_encrypt((const unsigned char *) buff, buff, total_len, key);
    memset(key, 0, sizeof(key));
    if (ret != 0) {
        db_serr("encrypt data false addr:%d ret:%d need:%d", addr, ret, total_len);
        return -1;
    }
    ret = writeNvmData(addr, buff, total_len, block, backup);
    if (ret != total_len) {
        db_serr("save data false addr:%d len:%d ret:%d", addr, total_len, ret);
        return -1;
    }
    return size;
}

static int readEncryptNvmData(int addr, void *data, int size, int block) {
    unsigned char buff[256] = {0};
    int len = readNvmData(addr, buff, sizeof(buff), block);
    if (len < 0) {
        db_msg("readNvmData error len=%d", len);
        return len;
    }
    if (len <= 4) {
        db_error("invalid read addr:%d ret:%d", addr, len);
        return 0;
    }
    unsigned char key[32];
    if (getPrivateAESKey(key) != 32) {
        db_serr("get AES key false");
        return -1;
    }
    int ret = aes256_decrypt(buff, buff, len, key);
    memset(key, 0, sizeof(key));
    if (ret != 0) {
        db_serr("decrypt data false addr:%d ret:%d", addr, ret);
        return -1;
    }
    len -= 4;
    sha256_Raw(buff, len, key);
    if (memcmp(buff + len, key, 4) != 0) {
        db_serr("decrypt data verify false addr:%d", addr);
        return -1;
    }
    if (size > len) size = len;
    memcpy(data, buff, size);
    return size;
}

static int writePrivateData(PrivateDataInfo *privdata) {
    if (NULL == privdata) {
        db_serr("invalid param");
        return -1;
    }
    gPrivDataCached = 0;
    int ret;
    unsigned char key[32];
    unsigned char buff[sizeof(PrivateDataPacker) + sizeof(PrivateDataInfo)];
    int is_empty = buffer_is_ff((const unsigned char *) privdata, sizeof(*privdata));
    if (is_empty) {
        memset(buff, 0xFF, sizeof(buff));
    } else {
        PrivateDataPacker *packer = (PrivateDataPacker *) buff;
        memset(buff, 0, sizeof(buff));
        memcpy(packer->check, gPrivatePackTag, PRIVATE_TAG_LEN);
        packer->version = PRIVATE_DATA_PACK_VERSION;
        packer->payload_len = sizeof(PrivateDataInfo);
        packer->header_len = sizeof(PrivateDataPacker);
        sha256_Raw((const unsigned char *) privdata, sizeof(PrivateDataInfo), packer->digest);
        memcpy(buff + sizeof(PrivateDataPacker), privdata, sizeof(PrivateDataInfo));

        if (getPrivateAESKey(key) != 32) {
            db_serr("get AES key false");
            return -1;
        }
        ret = aes256_encrypt(buff + 9, buff + 9, sizeof(PrivateDataPacker) + sizeof(PrivateDataInfo) - 9, key);
        memset(key, 0, sizeof(key));
        if (ret < 0) {
            db_serr("encrypt private data false");
            return -1;
        }
    }
    int area;
    int block = 0;
    ret = -1;
    do {
        area = PRIVATE_DATA_BASE_AREA + block * PRIVATE_DATA_BAKUP_OFFSET;
        ret = ddi_flash_write(area, buff, sizeof(buff));
        if (ret != sizeof(buff)) {
            db_serr("write private data block:%d ret=%d != %d", block, ret, sizeof(buff));
            break;
        }
        db_secure("write private data block:%d ret=%d", block, ret);

        if (block == 0) { //backup
            block++;
            continue;
        }
        ret = 0;
        break;
    } while (1);
    return ret;
}

static int decodePrivateDataV1(PrivateDataInfo *privdata, unsigned char *buff, int len) {
    db_serr("invalid V1 format");
    return -1;
}

static int checkPrivateDataInfo(PrivateDataInfo *privdata) {
    if (memcmp(privdata->check, gPrivateTag, 4) != 0) {
        db_serr("invalid private tag:%s", debug_bin_to_hex(privdata->check, 4));
        return -1;
    }
    if (privdata->version <= 1) {
        db_serr("invalid private version:%d", privdata->version);
        return -1;
    }

    if (device_check_sn(privdata->sn) != 0) {
        db_serr("invalid private sn:%s", privdata->sn);
        return -1;
    }

    if (!privdata->id[0]) {
        db_serr("invalid private id:%s", privdata->id);
        return -1;
    }
    if (!privdata->hostkey[0]) {
        db_serr("invalid private hostkey:%s", privdata->hostkey);
        return -1;
    }

    if (buffer_is_zero(privdata->se_hostkey, sizeof(privdata->se_hostkey))) {
        db_serr("empty se_hostkey");
        return -1;
    }
    if (buffer_is_zero(privdata->sign_data, sizeof(privdata->sign_data))) {
        db_serr("empty sign_data");
        return -1;
    }

    //check sign
    unsigned char signpub[33];
#ifdef BUILD_FOR_DEV
    if (privdata->sign_index == 1) { //dev
        unsigned char signpub1[33] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xef,
		};
        XDEFINE_BUFFER2(signpub, 33, signpub1);
    } else
#endif
    if (privdata->sign_index == 2) { //release
        unsigned char signpub2[] = {
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xef,
        };
        XDEFINE_BUFFER2(signpub, 33, signpub2);
    } else {
        db_serr("invalid sign_index:%d", privdata->sign_index);
        return -1;
    }
    XDEFINE_BUFFER1(signpub, 33);
    unsigned char digest[32];
    SHA256_CTX context;
    sha256_Init(&context);
    char cpuid[DEVICE_CPUID_BUFFSIZE] = {0};
    int ret = device_get_pub_cpuid(cpuid, DEVICE_CPUID_BUFFSIZE);
    if (ret != DEVICE_CPUID_LEN) {
        db_error("get cpuid false ret:%d", ret);
        return -1;
    }
    sha256_Update(&context, (const unsigned char *) cpuid, DEVICE_CPUID_LEN);
    sha256_Update(&context, (const unsigned char *) privdata->sn, sizeof(privdata->sn));
    sha256_Update(&context, (const unsigned char *) privdata->id, sizeof(privdata->id));
    sha256_Update(&context, &privdata->se_type, 1);
    sha256_Update(&context, privdata->se_hostkey, sizeof(privdata->se_hostkey));
    sha256_Final(&context, digest);

    db_secure("index:%d signpub:%s", privdata->sign_index, debug_ubin_to_hex(signpub, 33));
    db_secure("digest:%s", debug_ubin_to_hex(digest, 32));
    db_secure("sign_data:%s", debug_ubin_to_hex(privdata->sign_data, 64));
    ret = ecdsa_verify_digest(&secp256k1, signpub, privdata->sign_data, digest);
    memset(&digest, 0, sizeof(digest));
    memset(signpub, 0, sizeof(signpub));
    if (ret != 0) {
        db_serr("verify digest false index:%d, ret:%d", privdata->sign_index, ret);
        return -1;
    }
    return 0;
}

static int decodePrivateData(PrivateDataInfo *privdata, unsigned char *buff, int len) {
    PrivateDataPacker *packer = (PrivateDataPacker *) buff;
    PrivateDataInfo *pdata = (PrivateDataInfo *) (buff + sizeof(PrivateDataPacker));
    unsigned char key[32];
    if (packer->version != PRIVATE_DATA_PACK_VERSION) {
        db_secure("invalid pack version:%d", packer->version);
        return -1;
    }
    if (packer->header_len != (int) sizeof(PrivateDataPacker) || packer->payload_len != (int) sizeof(PrivateDataInfo) || ((int) sizeof(PrivateDataPacker) + (int) sizeof(PrivateDataInfo)) > len) {
        db_secure("invalid pack len:%d %d buff len:%d", packer->header_len, packer->payload_len, len);
        return -1;
    }
    if (getPrivateAESKey(key) != 32) {
        db_serr("get AES key false");
        return -1;
    }
    int ret = aes256_decrypt(buff + 9, buff + 9, (sizeof(PrivateDataPacker) + sizeof(PrivateDataInfo)) - 9, key);
    memset(key, 0, sizeof(key));
    if (ret != 0) {
        db_serr("decrypte false");
        return -1;
    }
    sha256_Raw((const unsigned char *) pdata, sizeof(PrivateDataInfo), key);
    if (memcmp(key, packer->digest, 32) != 0) {
        db_serr("digest diff expact:%s", debug_ubin_to_hex(packer->digest, 32));
        db_serr("data digest:%s", debug_ubin_to_hex(key, 32));
        return -1;
    }
    if (checkPrivateDataInfo(pdata) != 0) {
        db_serr("check private data false");
        return -1;
    }
    memcpy(privdata, pdata, sizeof(PrivateDataInfo));
    return 0;
}

static int readPrivateData(PrivateDataInfo *privdata, int block) {
    int readed, ret;
    unsigned char buff[sizeof(PrivateDataPacker) + (int) sizeof(PrivateDataInfo)];
    if (NULL == privdata || block < 0 || block > 2) {
        db_serr("invalid param");
        return -1;
    }
    if (block == 2 && Global_Skip_Boot_Private) {
        db_serr("skip read boot private");
        return -1;
    }
    privdata->version = 0;
    //const char *path;
    int area;
    if (block == 2) {
        area = BOOT0_PRIVATE_DATA_OFFSET;
        db_serr("should not come to there!!!");
        return -1;
    } else {
        //path = getPrivatePath();
        area = PRIVATE_DATA_BASE_AREA + block * PRIVATE_DATA_BAKUP_OFFSET;
    }

    ret = ddi_flash_read(area, buff, sizeof(buff));
    if (ret != sizeof(buff)) {
        db_secure("read data ret:%d != %d ", ret, sizeof(buff));
        return -3;
    }
    readed = sizeof(PrivateDataPacker) + sizeof(PrivateDataInfo);
    int init_state = -1;
    do {
        area = (buff[5] << 8) | buff[4]; //use as version
        if (memcmp(buff, gPrivatePackTag, PRIVATE_TAG_LEN) == 0) {
            if (area == PRIVATE_DATA_PACK_VERSION) {
                if (decodePrivateData(privdata, buff, readed) != 0) {
                    db_serr("decode private data false");
                    break;
                }
            } else {
                db_serr("invalid v2 version:%d", area);
                break;
            }
        } else if (memcmp(buff, gPrivateTag, PRIVATE_TAG_LEN) == 0) {
            if (area == PRIVATE_DATA_VERSION_V1) {
                if (decodePrivateDataV1(privdata, buff, readed) != 0) {
                    db_serr("decode private V1 data false");
                    break;
                }
            } else {
                db_serr("invalid v1 version:%d", area);
                break;
            }
        } else {
            db_serr("invalid private TAG,block:%d", block);
            break;
        }
        init_state = 0;
    } while (0);

    if (init_state != 0 && block < 1) {
        db_secure("try read bak:%d privdata", block + 1);
        return readPrivateData(privdata, block + 1);
    }
    return init_state;
}

static PrivateDataInfo *getPrivateDataInfo() {
    int ret;
    if (!gPrivDataCached) {
        ret = readPrivateData(gPrivateData, 0);
        gPrivDataCached = 1;
        if (ret != 0) {
            gPrivateData->version = 0;
            db_serr("readPrivateData false,ret:%d", ret);
        }
    }
    return gPrivateData->version ? gPrivateData : NULL;
}

static int getDeviceHostKey(char *hostkey, int len) {
    unsigned char digest[32] = {0};
    char cpu[DEVICE_CPUID_BUFFSIZE] = {0};
    if (len < HOSTKEY_SIZEOF) return -1;
    if (device_get_cpuid(cpu, sizeof(cpu)) <= 0) {
        return -1;
    }
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, (unsigned char *) "0123456789abcdef", 16);
    sha256_Update(&context, (unsigned char *) cpu, strlen(cpu));
    sha256_Update(&context, (unsigned char *) "0123456789abcdef", 16);
    sha256_Final(&context, digest);
    bin_to_hex(digest, 9, hostkey + 1);
    hostkey[0] = 'h';
    hostkey[19] = '\0';
    db_secure("hostkey:%s", hostkey);
    return 19;
}

int device_get_pub_cpuid(char *buf, int len) {
    if (NULL == buf || len <= DEVICE_CPUID_LEN) {
        db_serr("invalid param");
        return -1;
    }
    int retlen;
    const char *cpu = device_get_cpuid_p();
    if (!cpu) {
        db_serr("invalid cpuid");
        return -2;
    }
    memset(buf, 0, len);
    retlen = (int) strlen(cpu);
    if (retlen != DEVICE_CPUID_LEN) {
        db_serr("invalid cpuid retlen=%d", retlen);
        return -3;
    }
    uint8_t digest[32] = {0};
    uint8_t chipid[32] = {0};
    memset(chipid, 0, sizeof(chipid));
    if (sec_read_chipid(chipid) != 0) {
        db_error("get chipid false");
        return -4;
    }
    sha256_message(chipid, 32, (const uint8_t *) cpu, DEVICE_CPUID_LEN, digest);
    bin_to_hex(digest, DEVICE_CPUID_LEN / 2, buf);
    buf[0] = 'b';
    buf[retlen] = '\0';
    db_msg("change cpuid:%s", buf);
    return retlen;
}

int device_get_cpuid(char *buf, int len) {
    if (NULL == buf || len <= DEVICE_CPUID_LEN) {
        db_serr("invalid param");
        return -1;
    }
    int retlen;
    const char *cpu = device_get_cpuid_p();
    if (!cpu) {
        return -1;
    }
    memset(buf, 0, len);
    retlen = strlen(cpu);
    if (retlen != DEVICE_CPUID_LEN) {
        db_serr("invalid cpuid");
        return -1;
    }
    strncpy(buf, cpu, retlen);
    buf[retlen] = '\0';
    return retlen;
}

const char *device_get_cpuid_p(void) {
    int retlen;
    if (g_CpuId[0] == 0) {
        retlen = ddi_sec_get_cpuid((unsigned char *) g_CpuId, DEVICE_CPUID_BUFFSIZE);
        if (retlen != DEVICE_CPUID_LEN) {
            memset(g_CpuId, 0, DEVICE_CPUID_BUFFSIZE);
            db_serr("getCpuId false ret:%d", retlen);
            return NULL;
        }
        g_CpuId[DEVICE_CPUID_LEN] = 0;
    }
    db_msg("g_CpuId:%s", g_CpuId);

    return g_CpuId;
}

const char *device_get_diviceid_p() {
    return device_get_cpuid_p();
}

int device_get_id(char *buf, int len) {
    if (NULL == buf || len < 24) {
        db_serr("invalid param");
        return -1;
    }
    PrivateDataInfo *privdata = getPrivateDataInfo();
    if (privdata == NULL) {
        return -2;
    }
    int idlen = strlen(privdata->id);
    if (!idlen) {
        return -4;
    }
    if (idlen >= len) {
        idlen = len - 1;
    }
    memcpy(buf, privdata->id, idlen);
    buf[idlen] = '\0';
    return idlen;
}

int device_active(DeviceActiveInfo *info, int do_active) {
    int ret;
    PrivateDataInfo privdata;
    if (!info) {
        return -1;
    }

    if (device_check_sn(info->sn) != 0) {
        db_serr("check SN:%s false", info->sn);
        return -3;
    }

    if (!info->id[0]) {
        db_serr("invalid id");
        return -3;
    }

    if (buffer_is_zero(info->se_hostkey, sizeof(info->se_hostkey))) {
        db_serr("invalid se_hostkey");
        return -4;
    }

    if (info->se_type <= 0) {
        db_serr("invalid se_type");
        return -4;
    }

    if (!info->sign_index || buffer_is_zero(info->sign_data, 64)) {
        db_serr("invalid sing index:%d or data:%s", info->sign_index, debug_ubin_to_hex(info->sign_data, 64));
        return -4;
    }

    if (do_active) {
        if (buffer_is_zero(info->host_privkey, sizeof(info->host_privkey))) {
            db_serr("invalid host_privkey");
            return -4;
        }

        if (buffer_is_zero(info->se_pubkey, sizeof(info->se_pubkey))) {
            db_serr("invalid se_pubkey");
            return -4;
        }
    }

    initPrivateData(&privdata);
    if (getDeviceHostKey(privdata.hostkey, 20) != 19) {
        db_serr("gen hostkey false");
        return -5;
    }

    memcpy(privdata.sn, info->sn, sizeof(privdata.sn));
    memcpy(privdata.id, info->id, sizeof(privdata.id));
    memcpy(privdata.host_privkey, info->host_privkey, sizeof(privdata.host_privkey));
    privdata.se_type = info->se_type;
    memcpy(privdata.se_hostkey, info->se_hostkey, sizeof(privdata.se_hostkey));
    memcpy(privdata.se_pubkey, info->se_pubkey, sizeof(privdata.se_pubkey));
    privdata.inited = 1;
    privdata.sign_index = info->sign_index;
    memcpy(privdata.sign_data, info->sign_data, sizeof(privdata.sign_data));

    if (checkPrivateDataInfo(&privdata) != 0) {
        db_serr("check private data false");
        return -6;
    }

    if (do_active) {
        if (writePrivateData(&privdata) == 0) {
            db_secure("write active SN:[%s] OK", privdata.sn);
            ret = 0;
        } else {
            db_serr("write active sn [%s] False", privdata.sn);
            ret = -1;
        }
    } else {
        db_secure("check active info success");
        ret = 0;
    }
    memset(&privdata, 0, sizeof(PrivateDataInfo));
    return ret;
}

int device_del_active() {
    PrivateDataInfo privdata;
    memset(&privdata, 0xFF, sizeof(PrivateDataInfo));
    return writePrivateData(&privdata);
}

int device_is_inited() {
    PrivateDataInfo *privdata = getPrivateDataInfo();
    if (privdata == NULL) {
        db_serr("getPrivateDataInfo false");
        return 0;
    }
    return (privdata->sn[0] && privdata->inited && privdata->sign_index) ? 1 : 0;
}

int device_check_sn(const char *sn) {
    return 0;
}

int device_get_sn(char *buf, int len) {
    if (NULL == buf || len < 24) {
        db_serr("invalid param");
        return -1;
    }
    PrivateDataInfo *privdata = getPrivateDataInfo();
    if (privdata == NULL) {
        return -2;
    }
    db_secure("get SN:[%s]", privdata->sn);
    int snlen = strlen(privdata->sn);

    if (device_check_sn(privdata->sn) != 0) {
        db_serr("check SN:%s false", privdata->sn);
        return 0;
    }

    if (snlen >= len) {
        snlen = len - 1;
    }
    memcpy(buf, privdata->sn, snlen);
    buf[snlen] = '\0';
    return snlen;
}

int device_check_sechip() {
    unsigned char hostkey[16] = {0};
    PrivateDataInfo *pdata = getPrivateDataInfo();
    if (!pdata) {
        db_serr("get privdata false");
        return -1;
    }
    if (pdata->version == 1) {
        db_secure("skip check se hostkey");
        return 0;
    }
    int ret = sechip_get_hostkey(hostkey);
    if (ret <= 0) {
        db_serr("get se hostkey false");
        return -1;
    }
    if (memcmp(hostkey, pdata->se_hostkey, sizeof(pdata->se_hostkey)) != 0) {
        db_serr("DIFF se hostkey");
        return -1;
    }
    return 0;
}

int device_check_se_shake(const unsigned char *host_random, const unsigned char *se_sign) {
    PrivateDataInfo *privdata = getPrivateDataInfo();
    if (privdata == NULL) {
        db_serr("getPrivateDataInfo false");
        return 0;
    }
    if (!buffer_is_zero(privdata->se_pubkey, 33) && ecdsa_verify_digest(&secp256k1, privdata->se_pubkey, se_sign, host_random) != 0) {
        db_serr("verify shake sign false pubkey:%s", debug_ubin_to_hex(privdata->se_pubkey, 33));
        db_serr("se_sign:%s", debug_ubin_to_hex(se_sign, 64));
        return -1;
    }
    return 0;
}

int device_sign_se_shake(const unsigned char *se_random, unsigned char *host_sign) {
    PrivateDataInfo *privdata = getPrivateDataInfo();
    if (privdata == NULL) {
        db_serr("getPrivateDataInfo false");
        return -1;
    }

    if (buffer_is_zero(privdata->host_privkey, 32)) {
        db_serr("emoty host_privkey");
        return -1;
    }

    if (ecdsa_sign_digest(&secp256k1, privdata->host_privkey, se_random, host_sign, NULL, NULL) != 0) {
        db_serr("sign se random false");
        return -1;
    }
    return 0;
}

static int checkUserActiveInfo(UserActiveInfo *info) {
    PrivateDataInfo *privdata = getPrivateDataInfo();
    if (privdata == NULL) {
        db_serr("getPrivateDataInfo false");
        return -1;
    }
    if (info->tag[0] != 'U' || info->tag[1] != 'A' || info->version != 0x1) {
        db_serr("invalid version:%d TAG:%02x%02x", info->version, info->tag[0], info->tag[1]);
        return -1;
    }
    if (device_check_sn(info->sn) != 0) {
        db_serr("check SN:%s false", info->sn);
        return -3;
    }
    if (strcmp(privdata->sn, info->sn) != 0) {
        db_serr("DIFF SN:%s != %s", info->sn, privdata->sn);
        return -4;
    }
    if (info->time < 1564617600) {    //UTC 2019-08-01
        db_serr("invalid time:%d", info->time);
        return -5;
    }
    if (!info->sign_index || buffer_is_zero(info->sign_data, 64)) {
        db_serr("invalid sing index:%d or data:%s", info->sign_index, debug_ubin_to_hex(info->sign_data, 64));
        return -6;
    }


    char cpu[DEVICE_CPUID_BUFFSIZE] = {0};
    int ret = device_get_pub_cpuid(cpu, DEVICE_CPUID_BUFFSIZE);
    if (ret != DEVICE_CPUID_LEN) {
        db_serr("get cpu false");
        return -7;
    }

    //check sign
    unsigned char signpub[33];
#ifdef BUILD_FOR_DEV
    if (info->sign_index == 1) { //dev
        unsigned char signpub1[33] = {
			0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
			0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
			0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
			0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xef,
		};
        XDEFINE_BUFFER2(signpub, 33, signpub1);
    } else
#endif
    if (info->sign_index == 2) { //release
        unsigned char signpub2[] = {
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xef,
        };
        XDEFINE_BUFFER2(signpub, 33, signpub2);
    } else {
        db_serr("invalid sign_index:%d", info->sign_index);
        return -1;
    }
    XDEFINE_BUFFER1(signpub, 33);

    unsigned char digest[32];
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, (const unsigned char *) cpu, strlen(cpu));
    write_be(digest, info->time);
    sha256_Update(&context, digest, 4);
    sha256_Update(&context, (const unsigned char *) info->sn, sizeof(info->sn));
    sha256_Update(&context, (const unsigned char *) privdata->id, sizeof(privdata->id));
    sha256_Update(&context, &privdata->se_type, 1);
    sha256_Update(&context, privdata->se_hostkey, sizeof(privdata->se_hostkey));
    sha256_Final(&context, digest);

    //db_serr("signpub:%s", debug_ubin_to_hex(signpub, 33));
    //db_serr("digest:%s", debug_ubin_to_hex(digest, 32));
    ret = ecdsa_verify_digest(&secp256k1, signpub, info->sign_data, digest);
    memset(&digest, 0, sizeof(digest));
    memset(signpub, 0, sizeof(signpub));
    if (ret != 0) {
        db_serr("verify digest false");
        return -1;
    }
    return 0;
}

int device_get_user_active_info(UserActiveInfo *info) {
    memset(info, 0, sizeof(UserActiveInfo));
    int ret = readNvmData(NVM_ADDR_USER_ACTIVE_OFFSET, info, sizeof(UserActiveInfo), 0);
    if (ret != sizeof(UserActiveInfo)) {
        db_serr("read nvm false, ret:%d", ret);
        return -1;
    }
    unsigned char key[32];
    if (getPrivateAESKey(key) != 32) {
        db_serr("get AES key false");
        return -2;
    }
    ret = aes256_decrypt((const unsigned char *) info, (unsigned char *) info, sizeof(UserActiveInfo), key);
    memset(key, 0, sizeof(key));
    if (ret < 0) {
        db_serr("decrypt uactive data false, ret:%d", ret);
        return -3;
    }
    if (checkUserActiveInfo(info) != 0) {
        return -4;
    }
    return 0;
}

int device_get_active_time() {
    if (gActiveTime > 0) {
        return gActiveTime;
    }
    UserActiveInfo info;
    memset(&info, 0x0, sizeof(UserActiveInfo));
    int ret = device_get_user_active_info(&info);
    if (ret != 0) {
        db_serr("not user active info ret:%d", ret);
        return 0;
    }
    db_secure("set uactive time:%d time_zone:%d", info.time, info.time_zone);
    gActiveTime = info.time + info.time_zone;
    return gActiveTime;
}

int device_user_active(UserActiveInfo *info, int do_active) {
    int ret;
    if (!info) {
        return -1;
    }
    if (!device_is_inited()) {
        db_serr("device not inited");
        return -1;
    }

    ret = checkUserActiveInfo(info);
    if (ret != 0) {
        db_serr("check info false ret:%d", ret);
        return ret;
    }
    db_secure("active info PASS");
    if (!do_active) {
        return 0;
    }
    unsigned char key[32];
    unsigned char eninfo[sizeof(UserActiveInfo)];

    if (getPrivateAESKey(key) != 32) {
        db_serr("get AES key false");
        return -1;
    }

    ret = aes256_encrypt((const unsigned char *) info, eninfo, sizeof(UserActiveInfo), key);
    memset(key, 0, sizeof(key));
    if (ret < 0) {
        db_serr("encrypt uactive data false");
        return -1;
    }
    if (writeNvmData(NVM_ADDR_USER_ACTIVE_OFFSET, eninfo, sizeof(UserActiveInfo), 0, 1) == sizeof(UserActiveInfo)) {
        db_secure("save uactive OK");
    } else {
        db_serr("save uactive failed");
        return -1;
    }
    gActiveTime = -1;
    return 0;
}

int device_get_hw_break_state(int trytime) {
#ifdef CONFIG_DETECT_HW_BREAK
    int ret = 0;
    do {
        ret = ddi_sec_tamper_get_stat();
        if (ret == 0) {
            break;
        }
        db_serr("cover state:%d", ret);
        trytime--;
        if (trytime > 0) {
            ddi_sys_msleep(10);
        } else {
            break;
        }
    } while (1);
    return ret;
#else
    return 0;
#endif
}

uint64_t device_read_seed_account(void) {
    seed_info_t info;
    memset(&info, 0, sizeof(info));
    int ret = readEncryptNvmData(NVM_ADDR_SEED_INFO_OFFSET, &info, sizeof(info), 0);
    if (ret < 4) {
        return 0;
    }

    db_msg("info.id:%llx", info.id);

    return info.id;
}

int device_save_seed_account(uint64_t id) {
    seed_info_t info;
    int ret;
    if (!id) {
        ret = clearNvmData(NVM_ADDR_SEED_INFO_OFFSET, 32, 0);
        db_secure("clean account ret:%d", ret);
        return ret;
    } else {
        memset(&info, 0, sizeof(info));
        info.id = id;
        ret = writeEncryptNvmData(NVM_ADDR_SEED_INFO_OFFSET, &info, sizeof(info), 0, 1);
        db_secure("save account id:%llx ret:%d", id, ret);
        return ret;
    }
}

int device_read_settings(unsigned char *data, int size) {
    return readEncryptNvmData(NVM_ADDR_SETTINGS_OFFSET, data, size, 0);
}

int device_save_settings(const unsigned char *data, int size) {
    if (size > 120) {
        db_error("invalid size:%d", size);
        return -1;
    }
    return writeEncryptNvmData(NVM_ADDR_SETTINGS_OFFSET, data, size, 0, 0);
}

int device_clean_all_info(void) {
    clearNvmData(NVM_ADDR_SETTINGS_OFFSET, 128, 0);
    device_save_seed_account(0);
    return 0;
}
