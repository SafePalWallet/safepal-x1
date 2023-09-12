#ifndef WALLET_WALLET_UTIL_HW_H
#define WALLET_WALLET_UTIL_HW_H

#include "wallet_util.h"
#include "debug.h"

#ifdef DEBUG_ON

#define DEBUG_UART 1
#define DEBUG_USB 0

#if DEBUG_USB && DEBUG_UART
#error "debug mode can only be DEBUG_UART or DEBUG_USB, cannot be both"
#endif

#endif

#ifdef __cplusplus
extern "C" {
#endif

int get_mix_random_buffer(uint8_t *buf, size_t len);

int get_message_process_winid(const ProtoClientMessage *msg);

int get_coin_icon_path(int type, const char *uname, char *path, int size);


#ifdef DEBUG_ON

void s_printhex(const char *s, uint8_t *data, int len);

#define printhex(format, args...)    s_printhex(format, ##args)
#endif

#ifdef __cplusplus
}
#endif
#endif
