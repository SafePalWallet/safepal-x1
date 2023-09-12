
#ifndef _GUIDE_WIN_H
#define _GUIDE_WIN_H

#include "ex_types.h"

#define DEFAULT_SCREEN_SAVER_TIME 60
#define DEFAULT_MID_SCREEN_SAVER_TIME 180
#define DEFAULT_HI_SCREEN_SAVER_TIME 600
#define MAX_MNEMONIC_CNT  24
#define MAX_MNEMONIC_BUFFSIZE  32
#define IS_VALID_MNEMONIC_LEN(l) ( (l)>=12 && (l)<=24 && ( ((l)%3)==0 ))
#define ACCOUNT_TYPE_NEW_GEN    (1)
#define ACCOUNT_TYPE_RECOVERY   (2)

#define DEVICE_ACTIVE_REQUEST_URL		(1)
#define DEVICE_ACTIVE_REQUEST_DATA		(2)

int startGuide(void);

int setupLang(int param);

int enterRecoveryWord(char *mnemonics, int size, int mlen, const unsigned char *passwd, char flag, int eventType);

#endif
