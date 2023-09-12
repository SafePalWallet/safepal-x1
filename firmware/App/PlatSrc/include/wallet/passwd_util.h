#ifndef WALLET_PASSWD_UTIL_H
#define WALLET_PASSWD_UTIL_H

#include "common.h"
#include "key_event.h"
#include "defines.h"

enum {
    PIN_CODE_NONE = 0,
    PIN_CODE_CHECK = 1,
    PIN_CODE_VERITY = 2
};

typedef enum {
    USER_PASSWD_ERR_NONE = 0,
    USER_PASSWD_ERR_INVALID_PARAS = -1,
    USER_PASSWD_ERR_NOT_INPUT = -2,
    USER_PASSWD_ERR_FORMAT = -100,
    USER_PASSWD_ERR_WEAK = -150,
    USER_PASSWD_ERR_SYSTEM = -300,
    USER_PASSWD_ERR_VERIFY = -400,
    USER_PASSWD_ERR_ABORT = KEY_EVENT_ABORT,
} USER_PASSWD_ERR;

#define PASSKB_FLAG_RANDOM 1
#define PASSKB_FLAG_NOT_SWITCH_GUIDE 2
#define PASSKB_FLAG_RAW_PASSWD 4

int hash_user_passwd(const char *passwd, int len, unsigned char hash[PASSWD_HASHED_LEN]);

USER_PASSWD_ERR passwdKeyboard(HWND hParent, const char *title, int check, unsigned char passhash[PASSWD_HASHED_LEN],
                               unsigned int flag);

USER_PASSWD_ERR checkPasswdKeyboard(HWND hParent, const char *title, unsigned int flag);

#endif
