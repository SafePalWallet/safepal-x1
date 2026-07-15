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
#include "tx_common.h"

extern ProtoClientMessage *mMessage;
static TxPorcessData mTxp[1];
static DynamicViewCtx mDView[1];
static char *mRawDataStr;

static int doSignReq(void) {
    if (!mTxp->onSign) {
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
    ret = mTxp->onInit(mTxp->session);
    if (ret != 0) {
        db_error("TX init ret:%d", ret);
        dialog_error3(0, ret, res_getLabel(LANG_LABEL_UNSUPPORT_MSG));
        return RETURN_DISP_MAINPANEL;
    }

    dwin_init();
    //add verify code
    int n = TxGetVerifyCode(mMessage);
    if (n < 0) {
        db_error("TxGetVerifyCode error ret:%d", n);
        dialog_error3(0, n, "Failed to generate verification code. Please try again.");
        dwin_destory();
        return ret;
    }
    uint8_t msg[96] = {0};
    uint8_t code[8] = {0};
    for (int i = 0; i < 6; i++) {
        code[5 - i] = n % 10 + 0x30;
        n /= 10;
    }
    snprintf(msg, sizeof(msg), "%s:\n%s\n \n%s:", res_getLabel(LANG_LABEL_TX_VERIFY_CODE), code, res_getLabel(LANG_LABEL_TX_SHOW_DETAILS));
    dwin_add_txt(mDView, 0, 0, msg);

    ret = mTxp->onShow(mTxp->session, mDView);
    db_msg("TX show ret:%d", ret);
    if (ret < 0) {
        if (ret == -181) {
            dialog_error(0, res_getLabel(LANG_LABEL_WALLET_NO_SUPPORT_TOKEN));
        } else {
            dialog_error3(0, ret, res_getLabel(LANG_LABEL_UNSUPPORT_MSG));
        }
        dwin_destory();
        return RETURN_DISP_MAINPANEL;
    }

    //RawData
    int head_len = GetExtHeaderLen(mMessage);
    int raw_len = mMessage->data->len - head_len;
    if (mMessage->p_total > 1) {
        raw_len -= QR_HASH_CHECK_LEN;
    }
    int m_len = raw_len * 2 + 8;
    db_msg("mMessage->data->len:%d, head_len:%d, raw_len:%d", mMessage->data->len, head_len, raw_len);
    mRawDataStr = (char *) malloc(sizeof(char) * m_len);
    memzero(mRawDataStr, m_len);
    format_data_to_hex((unsigned char *) (mMessage->data->str + head_len), raw_len, mRawDataStr, m_len);
    dwin_add_txt(mDView, 0, 0, "Raw Data");
    dwin_add_txt(mDView, 0, 0, mRawDataStr);
    ret = ShowWindowTxt(mDView[0].coin_symbol, TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK));
    free(mRawDataStr);
    dwin_destory();
    if (ret != 0) {
        db_error("TX ShowWindowTxt error ret:%d", ret);
        return ret;
    }

    ret = doSignReq();

    return ret;
}
