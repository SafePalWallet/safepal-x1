#ifndef WALLET_COIN_ADAPTER_HW_H
#define WALLET_COIN_ADAPTER_HW_H

#include "dynamic_win.h"
#include "coin_util.h"
#include "debug.h"

#define view_add_txt(id, value) dwin_add_txt(view, 0, id, value)
#define view_add_txt_off(id, value, offset) dwin_add_txt_offset(view, 0, id, value,offset)

#ifdef VIEW_CODE_IN_IDE
#define df_on_sign_show NULL
#else
#define df_on_sign_show on_sign_show
#endif

#define sign_loading_win_start() loading_win_start(hwnd, "Signing", NULL, 0)

#ifdef __cplusplus
extern "C" {
#endif

void tx_set_db_view(const CoinConfig *config, DBTxCoinInfo *db, DynamicViewCtx *view);

void tx_set_db_view_info(DBTxCoinInfo *db, DynamicViewCtx *view, int coin_type, const char *coin_uname, const char *coin_name, const char *coin_symbol);

#ifdef __cplusplus
}
#endif
#endif
