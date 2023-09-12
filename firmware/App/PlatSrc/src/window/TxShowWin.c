#define LOG_TAG "TxShow"

#include "wallet_proto.h"
#include "coin_adapter.h"
#include "debug.h"
#include "Dialog.h"
#include "resource.h"
#include "passwd_util.h"
#include "dynamic_win.h"
#include "wallet_adapter.h"
#include "gui_sdk.h"
#include "ex_bt.h"

extern ProtoClientMessage *mMessage;
static TxPorcessData mTxp[1];
static int mShowRet = 0;
static DynamicViewCtx mDView[1];

int doSignReq(void) {
    db_msg("doSignReq");
    if (mShowRet != 0 || !mTxp->onSign) {
        db_error("invalid state");
        return -1;
    }
    unsigned char passhash[PASSWD_HASHED_LEN] = {0};
    int ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_PASSWD), PIN_CODE_VERITY, passhash, 1);
    //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
    if (ret < 0 || ret == RETURN_DISP_MAINPANEL) {
        db_error("input passwd ret:%d", ret);
        return ret;
    }
    uint16_t curv = coin_get_curv_id(mDView->coin_type, mDView->coin_uname);
    ret = mTxp->onSign(mTxp->session, 0, passhash);
    memzero(passhash, sizeof(passhash));
    if (ret == 0) {
        db_msg("TX sign Success");
    } else {
        db_error("TX sign false,ret:%d", ret);
        if (ret < 0) {
            dialog_error3(0, ret, "Sign tx failed.");
        }
        return RETURN_DISP_MAINPANEL;
    }
    return ret;
}

int TxShowWin(void) {
    char tmpbuf[128];
    db_msg("resume");
    //set_temp_screen_time(60);
    if (!mMessage) {
        db_error("invalid client msg");
        return -1;
    }
    int ret = tx_process_client_message(mMessage, mTxp);
    if (ret != 0) {
        dialog_system_error2(0, ret, "init", NULL);
        return 0;
    }
    if (!mTxp->onShow || !mTxp->onInit) {
        db_error("not show or init func");
        return -1;
    }
    mShowRet = mTxp->onInit(mTxp->session);
    if (mShowRet != 0) {
        db_error("TX init ret:%d", mShowRet);
        dialog_error3(0, mShowRet, "Init tx failed.");
        return RETURN_DISP_MAINPANEL;
    }

    dwin_init();
    mShowRet = mTxp->onShow(mTxp->session, mDView);
    ret = ShowWindowTxt(mDView[0].coin_symbol, TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK),
                        res_getLabel(LANG_LABEL_SUBMENU_OK));
    dwin_destory();
    if (ret != 0) {
        db_error("TX ShowWindowTxt error ret:%d", ret);
        return ret;
    }
    db_msg("TX show ret:%d", mShowRet);
    if (mShowRet < 0) {
        if (mShowRet == -181) {
            dialog_error(0, res_getLabel(LANG_LABEL_WALLET_NO_SUPPORT_TOKEN));
        } else {
            dialog_error3(0, mShowRet, "Show tx info failed.");
        }
        return RETURN_DISP_MAINPANEL;
    }

    ret = doSignReq();

    return ret;
}
