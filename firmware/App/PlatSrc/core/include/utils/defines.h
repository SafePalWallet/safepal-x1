#ifndef WALLET_DEFINES_H
#define WALLET_DEFINES_H

#include <stddef.h>
#include <stdint.h>

#if defined(BUILD_FOR_LOCAL_WALLET) || defined(BUILD_FOR_WEB)
typedef unsigned int HWND;
#endif

#define PASSWORD_MINI_LEN 6
#define PASSWORD_MAX_LEN 12
#define PASSWD_HASHED_LEN 32

#define COIN_SUPPORT_BTC_TAPROOT
#define COIN_SUPPORT_EOS

#endif
