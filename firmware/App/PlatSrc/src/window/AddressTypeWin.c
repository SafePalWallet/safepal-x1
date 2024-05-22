#define LOG_TAG "AddrTypeWin"

#include "debug.h"
#include "gui_sdk.h"
#include "gui_api.h"
#include "resource.h"
#include "MultiAddressWin.h"
#include "AddressTypeWin.h"

static int jumpWin(int param) {
    type_uname *p;
    p = (type_uname *) param;
    if (!p) {
        return -1;
    }
    int ret = 0;
    db_msg("p->chain_name%s", p->chain_name);
    if (!strcmp(p->chain_name, "BRC20") || !strcmp(p->chain_name, "Runes")) {
        ret = CoinDetailWin(param);
    } else if(p->type == COIN_TYPE_BITCOIN) {
        if ((!strncmp(COIN_UNAME_BTC4, p->uname, 5)) || (gSettings->mBtcMultiAddress == 0)) {
            db_msg("taproot", ret, p->uname);
            ret = CoinDetailWin(param);
        } else {
            ret = MultiAddressWin(param);
        }
    } else if(p->type == COIN_TYPE_SOLANA) {
        ret = CoinDetailWin(param);
    } else {
        ret = -2;
    }
    db_msg("AddressTypeWin jumpWin ret == %x p->uname=%s", ret, p->uname);
    return ret;
}

int update_menu(MENU_SET_CFG menu[4], type_uname param_list[4], int index, char pMenuText[4][20], type_uname *param, const char *uname, int type){
    if (index >= 4) {
        db_error("index err");
        return -10;
    }

    if(strlen(uname) > COIN_UNAME_BUFFSIZE) {
        db_error("uname err");
        return -11;
    }

    if(strlen(param->symbol) > COIN_SYMBOL_BUFFSIZE) {
        db_error("param->symbol len err");
        return -12;
    }

    memset(param_list[index].uname, 0, COIN_UNAME_BUFFSIZE);
    memset(param_list[index].symbol, 0, COIN_SYMBOL_BUFFSIZE);
    memset(param_list[index].chain_name, 0, COIN_NAME_BUFFSIZE);
    param_list[index].type = type;
    memcpy(param_list[index].uname, uname, strlen(uname));
    memcpy(param_list[index].symbol, param->symbol, strlen(param->symbol));
    memcpy(param_list[index].chain_name, param->chain_name, strlen(param->chain_name));
    menu[index].param = (uint32_t) &param_list[index];
    menu[index].pMenuText = (char *)pMenuText[index];
    return 0;
}

int AddressTypeWin(type_uname *param) {
    if (!param) {
        return -1;
    }
    db_msg("type:%x, uname:%s, symbol:%s, chain_name:%s", param->type, param->uname, param->symbol, param->chain_name);
    MENU_SET_CFG menu[4] = {
        {ID_NONE, VAL_OFF, SUB_ON, NULL, jumpWin, 0},
        {ID_NONE, VAL_OFF, SUB_ON, NULL, jumpWin, 0},
        {ID_NONE, VAL_OFF, SUB_ON, NULL, jumpWin, 0},
        {ID_NONE, VAL_OFF, SUB_ON, NULL, jumpWin, 0},
    };
	type_uname param_list[4];

    int index = 0, ret = 0;
    if (IS_BTC_COIN_TYPE(param->type)) {
        char *addr_uname = param->uname;
        if (!strcmp(addr_uname, "BTC")) {
            const char pMenuText[4][20] = {"Legacy", "SegWit", "Native SegWit", "Taproot"};
            ret = update_menu(menu, param_list, 0, pMenuText, param, "BTC", param->type);
            if (ret != 0) {return ret;}

            ret = update_menu(menu, param_list, 1, pMenuText, param, COIN_UNAME_BTC2, param->type);
            if (ret != 0) {return ret;}

            ret = update_menu(menu, param_list, 2, pMenuText, param, COIN_UNAME_BTC3, param->type);
            if (ret != 0) {return ret;}

            ret = update_menu(menu, param_list, 3, pMenuText, param, COIN_UNAME_BTC4, param->type);
            if (ret != 0) {return ret;}

            index = 4;
        } else if (!strcmp(addr_uname, "LTC")) {
            const char pMenuText[2][20] = {"Native SegWit", "Legacy"};
            ret = update_menu(menu, param_list, 0, pMenuText, param, "LTC", param->type);
            if (ret != 0) {return ret;}

            ret = update_menu(menu, param_list, 1, pMenuText, param, COIN_UNAME_LTC2, param->type);
            if (ret != 0) {return ret;}

            index = 2;
        } else if (!strcmp(addr_uname, "BCH")) {
            const char pMenuText[2][20] = {"CashAddr", "Legacy"};
            ret = update_menu(menu, param_list, 0, pMenuText, param, "BCH", param->type);
            if (ret != 0) {return ret;}

            ret = update_menu(menu, param_list, 1, pMenuText, param, COIN_UNAME_BCH2, param->type);
            if (ret != 0) {return ret;}

            index = 2;
        }

        db_msg("index:%d", index);
        if (index) {
            ret = gui_show_rich_menu(param->symbol, MENU_LIST | MENU_ICON_NUM, index, 0, menu);
            return ret;
        } else {
            if (gSettings->mBtcMultiAddress == 0) {
                ret = CoinDetailWin((int) param);
            } else {
                ret = MultiAddressWin(param);
            }
            return ret;
        }
    } else if (param->type == COIN_TYPE_BRC20 || param->type == COIN_TYPE_RUNE) {
        const char pMenuText[4][20] = {"Legacy", "SegWit", "Native SegWit", "Taproot"};
        ret = update_menu(menu, param_list, 0, pMenuText, param, "BTC", COIN_TYPE_BITCOIN);
        if (ret != 0) {return ret;}

        ret = update_menu(menu, param_list, 1, pMenuText, param, COIN_UNAME_BTC2, COIN_TYPE_BITCOIN);
        if (ret != 0) {return ret;}

        ret = update_menu(menu, param_list, 2, pMenuText, param, COIN_UNAME_BTC3, COIN_TYPE_BITCOIN);
        if (ret != 0) {return ret;}

        ret = update_menu(menu, param_list, 3, pMenuText, param, COIN_UNAME_BTC4, COIN_TYPE_BITCOIN);
        if (ret != 0) {return ret;}

        index = 4;
        ret = gui_show_rich_menu(param->symbol, MENU_LIST | MENU_ICON_NUM, index, 0, menu);
        return ret;
    } else if (param->type == COIN_TYPE_SOLANA) {
        const char pMenuText[2][20] = {"Optional", "Default"};
        ret = update_menu(menu, param_list, 0, pMenuText, param, COIN_UNAME_SOL2, param->type);
        if (ret != 0) {return ret;}

        ret = update_menu(menu, param_list, 1, pMenuText, param, "SOL", param->type);
        if (ret != 0) {return ret;}
        
        index = 2;
        ret = gui_show_rich_menu(param->symbol, MENU_LIST | MENU_ICON_NUM, index, 0, menu);
        return ret;
    }

    db_error("type err");
    return -1;
}

