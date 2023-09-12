#define LOG_TAG "CoinDetailWin"

#include "coin_util.h"
#include "bip32.h"
#include "ex_types.h"
#include "CoinDetailWin.h"
#include "debug.h"
#include "defines.h"
#include "passwd_util.h"
#include "gui_sdk.h"
#include "wallet_manager.h"
#include "dialog.h"
#include "coin_adapter.h"
#include "gui_api.h"
#include "cdrLang.h"
#include "cdr.h"
#include "ex_bt.h"
#include "resource.h"

static int showReceiveAddrList(int type, const char *uname, char *symbol) {
    int ret = 0;
    HDNode mHDNode;

    memzero(&mHDNode, sizeof(HDNode));
    ret = wallet_getHDNode(type, uname, &mHDNode);
    if (ret == -404) {
        unsigned char passhash[PASSWD_HASHED_LEN] = {0};
        ret = passwdKeyboard(0, "Enter PIN Code", PIN_CODE_VERITY, passhash, PASSKB_FLAG_RANDOM);
        //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        if (ret < 0 || ret == RETURN_DISP_MAINPANEL) {
            memzero(passhash, sizeof(passhash));
            db_error("input passwd ret:%d", ret);
            return ret;
        }
        ret = wallet_genDefaultPubHDNode(passhash, type, uname);
        memzero(passhash, sizeof(passhash));
        if (ret == 0) { //read again
            ret = wallet_getHDNode(type, uname, &mHDNode);
        }
    }
    if (ret != 0) {
        db_error("get hdnode false type:%d uname:%s ret:%d", type, uname, ret);
        dialog_error3(0, -402, "Addr generated failed.");
        return -1;
    }
    if (!GLobal_PIN_Passed) { //check passwd here,skip input passwd 2 times
        if (checkPasswdKeyboard(0, "Enter PIN Code", PASSKB_FLAG_RANDOM) != 0) {
            return 0;
        }
    }
    char address[MAX_ADDR_SIZE];
    const CoinConfig *coinConfig = getCoinConfig(type, uname);
    if (coinConfig == NULL) {
        coinConfig = getCoinConfigForMainType(type);
    }

    if (coinConfig == NULL) {
        db_error("coinConfig null");
        return -1;
    }

    db_msg("type:%d uname:%s", type, uname);
    ret = wallet_genAddress(address, sizeof(address), &mHDNode, type, uname, 0, 0);
    if (ret <= 0) {
        db_error("genAddress false type:%d uname:%s ret:%d", type, uname, ret);
        ret = dialog_error3(0, -403, "Address generated failed.");
        if (ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        }
        return -1;
    }

    int ret1 = gui_disp_info(symbol, address, TEXT_ALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                             res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);

    db_msg("showReceiveAddrList:%d EVENT_KEY_F1:%d", ret1, EVENT_KEY_F1);

    if (ret1 == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    }

    return ret;
}

int CoinDetailWin(int param) {
    type_uname *p = (type_uname *) param;
    if (!p) {
        return -1;
    }

    // if (IS_BTC_COIN_TYPE(p->type)) {
    //     db_error("CoinDetailWin not support BTC_COIN_TYPE");
    //     return -2;
    // }

    db_msg("type:%d,uname:%s symbol:%s", p->type, p->uname, p->symbol);
    return showReceiveAddrList(p->type, p->uname, p->symbol);
}

