#ifndef WALLET_SECURE_API_H
#define WALLET_SECURE_API_H

#include "stdint.h"

#define SECHIP_EXT_ID_LEN 16
#define SCHIP_CHIPID_SIZE 8

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned char chip_type;
    unsigned char chipid_len;
    unsigned char max_passwd_error_times;
    unsigned char _reserve;
    unsigned char chipid[SCHIP_CHIPID_SIZE];
    uint32_t app_version;
} sec_base_info;

typedef struct {
    unsigned char seed_state; // 0 none 1 seted 2 destroyed
    unsigned char mnemonic; // 0 none 1 seted
    uint16_t set_seed_times;
    uint16_t passwd_error_times;
    uint64_t account_id;
} sec_state_info;

enum {
    ERROR_SYSTEM_INNER = -0x50,
    ERROR_NVM_NOT_WRITEABLE = -0x51,
    ERROR_PASSWD_NO_MATCH = -0x60,
    ERROR_PASSWD_NOT_SETED = -0x61,
    ERROR_PASSWD_ERROR_MUCH = -0x62,
    ERROR_SERVICE_DENY = -0x66,
};

enum {
    PASSWD_STATE_NONE,    //not initd
    PASSWD_STATE_COMMON,    //common
    PASSWD_STATE_ERROR_COUNT, //count passwd error times
    PASSWD_STATE_DENY, // error too much,service deny
};

extern int sapi_subcode;

int sechip_get_id(unsigned char id[SECHIP_EXT_ID_LEN]);

int sechip_get_hostkey(unsigned char hostkey[16]);

int sapi_init0();

int sapi_reset();

int sapi_init();

void sapi_destory();

int sapi_get_base_info(sec_base_info *info);

int sapi_get_state_info(sec_state_info *info);

uint64_t sapi_get_account_id();

int sapi_encode_data(const unsigned char *passwd, int passlen, uint8_t encode_type, const unsigned char *data, int len, unsigned char *encode_data, int size);

int sapi_get_xpub(uint16_t curv, const char *path, const unsigned char *passwd, int passlen, unsigned char *xpub, unsigned int size);

int sapi_sign_digest(uint16_t curv, const char *path, const unsigned char *passhash, unsigned char sz_passhash,
                     const unsigned char *data, unsigned int size, unsigned char check_func, unsigned char *out, unsigned int outsize);

int sapi_change_passwd(const unsigned char *oldpasswd, int oldlen, const unsigned char *newpasswd, int newlen);

int sapi_check_passwd(const unsigned char *oldpasswd, int oldlen);

int sapi_store_seed(const unsigned char *seed, int seedlen, const unsigned char *passwd, int passlen);

int sapi_destory_seed();

int sapi_verify_mnemonic(const unsigned char *passwd, int passlen, const unsigned char *mnemonic, int len);

int sapi_set_passphrase(const unsigned char *passwd, int passlen, const unsigned char *data, int len);

#ifdef __cplusplus
}
#endif
#endif
