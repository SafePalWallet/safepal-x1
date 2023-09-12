#ifndef WALLET_DYNAMIC_WIN_H
#define WALLET_DYNAMIC_WIN_H

#include "storage_manager.h"
#include "cstr.h"
#include "debug.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    //---- in -----
    HWND hwnd;
    int msg_from;
    int show_more;
    //---- out ----
    cstring labels[1];
    int has_more;
    int total_height;
    int coin_type;
    uint32_t flag;
    const char *coin_uname;
    const char *coin_name;
    const char *coin_symbol;
    DBTxCoinInfo db;
} DynamicViewCtx;

int dwin_init(void);

int dwin_destory(void);

int dwin_add_txt(DynamicViewCtx *view, int mkey, int id, const char *value);

int dwin_add_txt_offset(DynamicViewCtx *view, int mkey, int id, const char *value, int offset);

int ShowWindowTxt(const char *pTitle, uint32_t tType, const char *pCancel, const char *pOk);

int SetWindowMText(HWND hWnd, const char *spString);

#ifdef __cplusplus
}
#endif
#endif
