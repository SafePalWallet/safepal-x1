#define LOG_TAG "Verify"

#include "VerifyWin.h"
#include "debug.h"
#include "Dialog.h"
#include "passwd_util.h"
#include "Stack.h"
#include "Passphrase.h"
#include "GuideWIn.h"
#include "cdrLang.h"
#include "gui_sdk.h"
#include "gui_event.h"
#include "secure_api.h"
#include "wallet_manager.h"
#include "gui_api.h"
#include "resource.h"
#include "common_util.h"
#include "ex_bt.h"

typedef enum {
    OP_INDEX_VERIFY_TIPS = 1,
    OP_INDEX_ENTER_PASSWD,
    OP_INDEX_SELECT_PASSPHRASE_TYPE,
    OP_INDEX_FIRST_USE_PASSPHRASE_TIPS,
    OP_INDEX_SELECT_MNEMONIC_CNT,
    OP_INDEX_VERIFY_MNEMONIC_TIPS,
    OP_INDEX_VERIFY_MNEMONIC,
    OP_INDEX_ENTER_PASSPHRASE,
    OP_INDEX_SAVE_PASSPHRASE,
    OP_INDEX_WALLET_NAME_TIPS,
    OP_INDEX_MAX
} guideIndex;

int get_have_mnemonic() {
    sec_state_info info;
    info.mnemonic = 0;
    if (sapi_get_state_info(&info) != 0) {
        db_serr("get state info false");
        return -1;
    }
    if (info.seed_state != 1) {
        return -1;
    }
    return info.mnemonic;
}

int VerifyWinGuide() {
    int nextIndex;
    int passwd_ok = 0;
    unsigned char passhash[PASSWD_HASHED_LEN] = {0};
    char mnenonics[MNEMONIC_MAX_LEN * MAX_MNEMONIC_CNT] = {0};
    int mChangeWin = 0;

    int mlen = 0;
    int ret = 0;
    int have_mnemonic = get_have_mnemonic();
    uint64_t old_account_id = wallet_AccountId();
    db_msg("have_mnemonic:%d old_account_id:%llx", have_mnemonic, old_account_id);
    if (have_mnemonic < 0 || !old_account_id) {
        dialog_error3(0, -401, "Seed verify failed.");
        return -1;
    }
    Stack *stack = newSlack(20);
    if (!stack) {
        return -1;
    }
    pushData(stack, OP_INDEX_VERIFY_TIPS);

    int32_t eventType = EVENT_NONE;
    do {
        ret = 0;
        nextIndex = getStackTop(stack);
        db_msg("next index:%d", nextIndex);
        switch (nextIndex) {
            case OP_INDEX_VERIFY_TIPS: {
                ret = gui_disp_info(res_getLabel(LANG_LABEL_ITEM_VERIFY), res_getLabel(LANG_LABEL_VERIFY_TIPS),
                                    TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                   res_getLabel(LANG_LABEL_SUBMENU_OK), eventType);
                if (ret == EVENT_OK) {
                    pushData(stack, OP_INDEX_ENTER_PASSWD);
                } else if (ret == EVENT_KEY_F1) {
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                } else {
                    nextIndex = OP_INDEX_MAX; //exit
                }
            }
                break;
            case OP_INDEX_ENTER_PASSWD: {
                popData(stack);
                set_temp_screen_time(DEFAULT_HI_SCREEN_SAVER_TIME);
                if (!passwd_ok || buffer_is_zero(passhash, sizeof(passhash))) {
                    memzero(passhash, sizeof(passhash));
                    ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_PASSWD), PIN_CODE_VERITY, passhash,
                                         PASSKB_FLAG_RANDOM);
                    //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
                } else {
                    ret = 0;
                }
                if (ret == KEY_EVENT_ABORT) {
                    memzero(passhash, sizeof(passhash));
                    nextIndex = OP_INDEX_MAX; //exit
                } else if (ret < 0) {
                    memzero(passhash, sizeof(passhash));
                    if (ret == USER_PASSWD_ERR_VERIFY) {
                        nextIndex = OP_INDEX_MAX;
                    }
                    break;
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    memzero(passhash, sizeof(passhash));
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                } else {
                    passwd_ok = 1;
                    pushData(stack, OP_INDEX_SELECT_MNEMONIC_CNT);
                }
            }
                break;
            case OP_INDEX_SELECT_MNEMONIC_CNT: {
                ret = selectMnemonicCnt(eventType);
                if (ret == KEY_EVENT_BACK) {
                    memzero(passhash, sizeof(passhash));
                    popData(stack);
                } else if (IS_VALID_MNEMONIC_LEN(ret)) {
                    mlen = ret;
                    pushData(stack, OP_INDEX_VERIFY_MNEMONIC);
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    memzero(passhash, sizeof(passhash));
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                }
            }
                break;
            case OP_INDEX_VERIFY_MNEMONIC: {
                if (!IS_VALID_MNEMONIC_LEN(mlen)) {
                    break;
                }
                memzero(mnenonics, sizeof(mnenonics));
                ret = enterRecoveryWord(mnenonics, MNEMONIC_MAX_LEN * mlen, mlen, passhash, 1, eventType);
                memzero(mnenonics, sizeof(mnenonics));
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (ret == 0 || ret == 88) { //verify oK or exit
                    popData(stack);
                    nextIndex = OP_INDEX_MAX;
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    memzero(passhash, sizeof(passhash));
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                }
            }
                break;
            default:
                break;
        }
        set_temp_screen_time(DEFAULT_SCREEN_SAVER_TIME);
        if (nextIndex != OP_INDEX_MAX && !is_key_event_value(ret) && ret < 0) {
            dialog_error3(0, -(nextIndex * 1000) + ret, "Seed verify failed.");
            nextIndex = OP_INDEX_VERIFY_TIPS;
        }

        ddi_sys_msleep(50);
    } while (nextIndex != OP_INDEX_MAX);
    memzero(passhash, sizeof(passhash));
    memzero(mnenonics, sizeof(mnenonics));
    ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
    freeSlack(stack);

    if (mChangeWin == RETURN_DISP_MAINPANEL) {
        return RETURN_DISP_MAINPANEL;
    }

    return 0;
}
