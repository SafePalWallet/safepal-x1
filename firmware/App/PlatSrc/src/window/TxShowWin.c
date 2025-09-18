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
static char *mRawDataStr;

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

static int GetExtHeaderLen(const ProtoClientMessage *msg) {
    size_t len = 0;
    if (msg && msg->data) {
        if (msg->flag & QR_FLAG_HAS_TIME) {
            len += 6;
            if (msg->data->len < len) { //error
                db_error("invalid data len:%d < time len:6", msg->data->len);
                return -1;
            }
        }
        if (msg->flag & QR_FLAG_EXT_HEADER) {
            if (msg->data->len < (len + 11)) {
                db_error("invalid data len:%d from len:%d", msg->data->len, len);
                return -2;
            }
            if (msg->data->str[len] != 0x7a) { //tag string 15
                return -3;
            }
            uint32_t low = 0;
            uint32_t hi = 0;
            len += 1;
            len += pb_decode((uint8_t *) (msg->data->str + len), &low, &hi); //varlen
            if (hi != 0 || low >= 0x4000) {
                db_error("invalid ext header var len:%d %d", low, hi);
                return -4;
            }
            len += low;
            if (msg->data->len < len) {
                db_error("invalid data len:%d < %d varlen:%d", msg->data->len, len, low);
                return -5;
            }
        }
    }
    return (int) len;
}

static int TxGetVerifyCode(const ProtoClientMessage *msg) {
    SHA256_CTX context;
    char sn[24];
    int ret;
    char unique_id[CLIENT_UNIQID_MAX_LEN + 1];
    char str[32];
    uint8_t digest[32];

    sha256_Init(&context);

    //sn
    memzero(sn, sizeof(sn));
    ret = device_get_sn(sn, 24);
    if (ret <= 0) {
        db_error("get SN error, ret:%d", ret);
        return -10;
    }
    db_msg("sn:%s", sn);
    sha256_Update(&context, sn, ret);
    //unique_id
    memzero(unique_id, sizeof(unique_id));
    ret = storage_queryClientUniqueId(msg->client_id, unique_id);
    if ((ret != 0) || (!is_safe_string(unique_id, CLIENT_UNIQID_MAX_LEN))) {
        db_error("get unique id error, ret:%d", ret);
        return -11;
    }
    db_msg("unique_id:%s", unique_id);
    sha256_Update(&context, unique_id, strlen(unique_id));
    //client_id
    memzero(str, sizeof(str));
    snprintf(str, sizeof(str), "%d", msg->client_id);
    db_msg("msg->client_id:%d, str:%s", msg->client_id, str);
    sha256_Update(&context, str, strlen(str));
    //account_id
    uint64_t account_id = wallet_AccountId();
    db_msg("account_id:%u, msg->account_id:%u", (uint32_t) account_id, msg->account_id);
    if ((uint32_t) account_id != msg->account_id) {
        db_error("not same, local (uint32_t) account_id:%u, msg->account_id:%u", (uint32_t) account_id, msg->account_id);
        return -12;
    }
    memzero(str, sizeof(str));
    snprintf(str, sizeof(str), "%u", msg->account_id);
    db_msg("account_id:%s", str);
    sha256_Update(&context, str, strlen(str));
    //data
    int ext_header_len = GetExtHeaderLen(msg);
    db_msg("ext_header_len:%d, msg->data->len:%d", ext_header_len, msg->data->len);
    if (ext_header_len < 0) {
        db_error("get ext header false ext_header_len:%d", ext_header_len);
        return -13;
    }
    int data_len = msg->data->len - ext_header_len;
    if (msg->p_total > 1) {
        data_len -= QR_HASH_CHECK_LEN;
    }
    sha256_Update(&context, msg->data->str + ext_header_len, data_len);
    sha256_Final(&context, digest);
    db_msg("digest:%s", debug_ubin_to_hex(digest, 32));
    sha256_Raw(digest, 32, digest);
    db_msg("digest:%s", debug_ubin_to_hex(digest, 32));
    unsigned int n = read_be(digest);
    n = n % 1000000;
    if (!n) n = 1;
    return n;
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
    mShowRet = mTxp->onInit(mTxp->session);
    if (mShowRet != 0) {
        db_error("TX init ret:%d", mShowRet);
        dialog_error3(0, mShowRet, "Init tx failed.");
        return RETURN_DISP_MAINPANEL;
    }

    dwin_init();

    //add verify code
    int n = TxGetVerifyCode(mMessage);
    if (n < 0) {
        db_error("TxGetVerifyCode error ret:%d", ret);
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

    mShowRet = mTxp->onShow(mTxp->session, mDView);

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
