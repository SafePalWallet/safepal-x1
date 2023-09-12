#ifndef WALLET_WIDGETS_H
#define WALLET_WIDGETS_H

#include "misc.h"
#include "cdr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHOW_QR_FLAG_RAW_DATA 0x10000

int showQRWindow(HWND hParent, int client_id, unsigned int flag, int msgtype, const unsigned char *qrdata, int size);

#ifdef __cplusplus
}
#endif

#endif
