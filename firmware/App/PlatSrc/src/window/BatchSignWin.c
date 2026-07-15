#define LOG_TAG "BatchSign"

#include "BatchSignWin.h"
#include "wallet_proto.h"
#include "coin_adapter.h"
#include "coin_adapter_hw.h"
#include "debug.h"
#include "Dialog.h"
#include "resource.h"
#include "passwd_util.h"
#include "dynamic_win.h"
#include "wallet_adapter.h"
#include "tx_common.h"
#include "common_core.h"
#include "common_util.h"

extern ProtoClientMessage *mMessage;

static TxPorcessData mTxp[1];
static DynamicViewCtx mDView[1];

static BatchSignParsedItem mItems[BATCH_MAX_TX_COUNT];
static int mCount;

// menu: [0] verify-code label, [1] verify-code value, [2] Sign,
//       [3] "View Data" hint, [4..] one per tx
#define BS_FIXED_ROWS 4
#define BS_MENU_MAX   (BATCH_MAX_TX_COUNT + BS_FIXED_ROWS)
static MENU_SET_CFG mMenu[BS_MENU_MAX];
static char mMenuText[BS_FIXED_ROWS][BATCH_TX_NAME_MAX_LEN]; // 0=label 1=code 2=Sign 3=View Data
static uint8_t mSkip[BS_MENU_MAX]; // 1 = info row, cursor skips it

// One menu row is 21 chars wide (uiMaxCharNums); reserve room for margins and
// the trailing ">" indicator, then ellipsize names that don't fit.
#define BS_NAME_DISP_MAX 18
static char mTxName[BATCH_MAX_TX_COUNT][BS_NAME_DISP_MAX + 1];

// doSignAll() return codes (internal)
#define BS_SIGN_DONE   0   // all signed, result QR sent
#define BS_SIGN_STAY   1   // PIN cancelled, stay on menu

// Show one transaction's detail page (coin onShow output + raw data).
static int showItemDetail(int i) {
    int ret = tx_process_client_message(mItems[i].msg, mTxp);
    if (ret != 0) {
        dialog_system_error2(0, ret, "init", NULL);
        return 0;
    }
    if (!mTxp->onShow || !mTxp->onInit) {
        db_error("not show or init func");
        return 0;
    }
    ret = mTxp->onInit(mTxp->session);
    if (ret != 0) {
        db_error("detail init ret:%d", ret);
        dialog_error3(0, ret, res_getLabel(LANG_LABEL_UNSUPPORT_MSG));
        goto end;
    }

    dwin_init();
    ret = mTxp->onShow(mTxp->session, mDView);
    if (ret < 0) {
        if (ret == -181) {
            dialog_error(0, res_getLabel(LANG_LABEL_WALLET_NO_SUPPORT_TOKEN));
        } else {
            dialog_error3(0, ret, res_getLabel(LANG_LABEL_UNSUPPORT_MSG));
        }
        dwin_destory();
        goto end;
    }

    // RawData (item data is a bare body, ext_header len is 0)
    int head_len = GetExtHeaderLen(mItems[i].msg);
    if (head_len < 0) head_len = 0;
    int raw_len = mItems[i].msg->data->len - head_len;
    if (raw_len > 0) {
        int m_len = raw_len * 2 + 8;
        char *raw = (char *) malloc(m_len);
        if (raw) {
            memzero(raw, m_len);
            format_data_to_hex((unsigned char *) (mItems[i].msg->data->str + head_len), raw_len, raw, m_len);
            dwin_add_txt(mDView, 0, 0, "Raw Data");
            dwin_add_txt(mDView, 0, 0, raw);
            free(raw);
        }
    }
    // OK and Back both return to the list (prototype 2.png)
    ShowWindowTxt(mDView[0].coin_symbol, TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK));
    dwin_destory();

end:
    if (mTxp->onEnd) {
        mTxp->onEnd(mTxp->session);
    }
    memset(mTxp, 0, sizeof(TxPorcessData));
    return 0;
}

// Pack all collected results into a single response QR (mirrors single-sign framing).
static int showBatchResult(const BatchSignRespEntry *entries, int rc) {
    if (rc <= 0) {
        return -1;
    }
    struct pbc_wmessage *resp = NULL;
    int ret = proto_build_batch_sign_response(&resp, entries, rc);
    if (ret != 0 || !resp) {
        db_error("build batch resp false:%d", ret);
        return -1;
    }
    struct pbc_slice slice;
    pbc_wmessage_buffer(resp, &slice);
    ret = showQRWindow(0, mMessage->client_id, mMessage->flag, QR_MSG_BATCH_SIGN_RESP,
                       (const unsigned char *) slice.buffer, (int) slice.len);
    proto_delete_wmessage(resp);
    return ret;
}

// Single PIN, sign every transaction, send one result QR. Abort whole batch on
// any failure.
static int doSignAll(void) {
    unsigned char passhash[PASSWD_HASHED_LEN] = {0};
    int ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_PASSWD), PIN_CODE_VERITY, passhash, 1);
    if (ret < 0 || ret == RETURN_DISP_MAINPANEL) {
        db_msg("pin cancel ret:%d", ret);
        memzero(passhash, sizeof(passhash));
        return BS_SIGN_STAY;
    }

    BatchSignRespEntry entries[BATCH_MAX_TX_COUNT];
    int rc = 0;
    gBatchSignCollector.active = 1;

    for (int i = 0; i < mCount; i++) {
        ret = tx_process_client_message(mItems[i].msg, mTxp);
        if (ret != 0) goto fail;
        if (!mTxp->onInit || !mTxp->onSign) {
            ret = -1;
            goto fail;
        }
        ret = mTxp->onInit(mTxp->session);
        if (ret != 0) goto fail;
        ret = mTxp->onSign(mTxp->session, 0, passhash); // result captured by collector
        if (ret != 0) goto fail;
        if (!gBatchSignCollector.data) {
            db_error("no sign result for tx:%d", i);
            ret = -1;
            goto fail;
        }
        entries[rc].msg_type = gBatchSignCollector.msg_type;
        entries[rc].data = gBatchSignCollector.data; // transfer ownership
        entries[rc].size = gBatchSignCollector.size;
        gBatchSignCollector.data = NULL;
        rc++;
        if (mTxp->onEnd) {
            mTxp->onEnd(mTxp->session);
        }
        memset(mTxp, 0, sizeof(TxPorcessData));
    }

    gBatchSignCollector.active = 0;
    memzero(passhash, sizeof(passhash));

    ret = showBatchResult(entries, rc);
    for (int i = 0; i < rc; i++) {
        free((void *) entries[i].data);
        entries[i].data = NULL;
    }
    if (ret != 0) {
        dialog_error3(0, ret, "Send sign result failed.");
        return RETURN_DISP_MAINPANEL;
    }
    return BS_SIGN_DONE;

fail:
    gBatchSignCollector.active = 0;
    if (gBatchSignCollector.data) {
        free(gBatchSignCollector.data);
        gBatchSignCollector.data = NULL;
    }
    memzero(passhash, sizeof(passhash));
    for (int j = 0; j < rc; j++) {
        free((void *) entries[j].data);
        entries[j].data = NULL;
    }
    if (mTxp->onEnd) {
        mTxp->onEnd(mTxp->session);
    }
    memset(mTxp, 0, sizeof(TxPorcessData));
    db_error("batch sign fail ret:%d", ret);
    if (ret < 0) {
        dialog_error3(0, ret, "Sign tx failed.");
    }
    return RETURN_DISP_MAINPANEL;
}

static void buildMenu(int code) {
    memset(mMenu, 0, sizeof(mMenu));
    memset(mSkip, 0, sizeof(mSkip));
    mSkip[0] = mSkip[1] = mSkip[3] = 1; // code label, code value, "View Data" hint
    // row 0: verification code label (info, not actionable)
    snprintf(mMenuText[0], sizeof(mMenuText[0]), "%s", res_getLabel(LANG_LABEL_TX_VERIFY_CODE));
    mMenu[0].id = ID_NONE;
    mMenu[0].has_val = VAL_OFF;
    mMenu[0].has_sub = SUB_OFF;
    mMenu[0].pMenuText = mMenuText[0];
    // row 1: verification code value (info, not actionable)
    snprintf(mMenuText[1], sizeof(mMenuText[1]), "%06d", code);
    mMenu[1].id = ID_NONE;
    mMenu[1].has_val = VAL_OFF;
    mMenu[1].has_sub = SUB_OFF;
    mMenu[1].pMenuText = mMenuText[1];
    // row 2: Sign
    snprintf(mMenuText[2], sizeof(mMenuText[2]), res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG));
    mMenu[2].id = ID_NONE;
    mMenu[2].has_val = VAL_OFF;
    mMenu[2].has_sub = SUB_ON;
    mMenu[2].pMenuText = mMenuText[2];
    // row 3: "View Data" hint (info, not actionable)
    snprintf(mMenuText[3], sizeof(mMenuText[3]), res_getLabel(LANG_LABEL_TX_SHOW_DETAILS));
    mMenu[3].id = ID_NONE;
    mMenu[3].has_val = VAL_OFF;
    mMenu[3].has_sub = SUB_OFF;
    mMenu[3].pMenuText = mMenuText[3];
    // rows 4..: one per transaction
    for (int i = 0; i < mCount; i++) {
        mMenu[BS_FIXED_ROWS + i].id = ID_NONE;
        mMenu[BS_FIXED_ROWS + i].has_val = VAL_OFF;
        mMenu[BS_FIXED_ROWS + i].has_sub = SUB_ON;
        omit_tail_string(mTxName[i], mItems[i].name, BS_NAME_DISP_MAX);
        mMenu[BS_FIXED_ROWS + i].pMenuText = mTxName[i];
    }
}

int BatchSignWin(void) {
    db_msg("resume");
    if (!mMessage) {
        db_error("invalid client msg");
        return -1;
    }

    mCount = proto_parse_batch_sign_request(mMessage, mItems, BATCH_MAX_TX_COUNT);
    if (mCount <= 0) {
        db_error("parse batch sign false:%d", mCount);
        dialog_error3(0, mCount, res_getLabel(LANG_LABEL_UNSUPPORT_MSG));
        return RETURN_DISP_MAINPANEL;
    }

    int code = TxGetVerifyCode(mMessage);
    if (code < 0) {
        db_error("TxGetVerifyCode error ret:%d", code);
        dialog_error3(0, code, "Failed to generate verification code. Please try again.");
        proto_free_batch_sign_items(mItems, mCount);
        mCount = 0;
        return RETURN_DISP_MAINPANEL;
    }

    buildMenu(code);

    int total = mCount + BS_FIXED_ROWS;
    int curInx = 2; // default selection: "Sign"
    int result = KEY_EVENT_ABORT;

    while (1) {
        int ret = gui_show_rich_menu_skip(res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG), MENU_LIST, total, curInx, mMenu,
                                          INFO_OK, INFO_BACK, EVENT_KEY_F1, mSkip);
        if (ret >= 0 && ret < total) {
            curInx = ret;
            if (ret == 2) {
                int r = doSignAll();
                if (r == BS_SIGN_DONE) {
                    result = 0;
                    break;
                } else if (r == BS_SIGN_STAY) {
                    continue;
                } else {
                    result = RETURN_DISP_MAINPANEL;
                    break;
                }
            } else if (ret >= BS_FIXED_ROWS) {
                showItemDetail(ret - BS_FIXED_ROWS);
                continue;
            } else {
                // rows 0/1/3 are skip rows, cursor can not land here; keep as guard
                continue;
            }
        } else {
            db_msg("menu exit ret:%d", ret);
            result = (ret == RETURN_DISP_MAINPANEL) ? RETURN_DISP_MAINPANEL : KEY_EVENT_ABORT;
            break;
        }
    }

    proto_free_batch_sign_items(mItems, mCount);
    mCount = 0;
    return result;
}
