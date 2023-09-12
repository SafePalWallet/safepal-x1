#define LOG_TAG "Passphrase"

#include "debug.h"
#include "ex_types.h"
#include "gui_api.h"
#include "wallet_util.h"
#include "Passphrase.h"
#include "gui_sdk.h"
#include "key_event.h"
#include "GuideWin.h"
#include "Stack.h"
#include "cdrLang.h"
#include "passwd_util.h"
#include "VerifyWin.h"
#include "wallet_manager.h"
#include "storage_manager.h"
#include "resource.h"
#include "storage_manager.h"
#include "dialog.h"
#include "common_util.h"
#include "ex_bt.h"

static int gMmenCntVals[MNEMNONIC_CNT_LEVEL_MAX] = {12, 15, 18, 21, 24};
static const char *gMmenCntStr[MNEMNONIC_CNT_LEVEL_MAX] = {"12", "15", "18", "21", "24"};

typedef enum {
    OP_INDEX_PASSPHRASE_TIPS = 1,
    OP_INDEX_PASSPHRASE_DETAIL_TIPS,
    OP_INDEX_ACTION_DETECTION,
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

int saveWalletName(const char *passphrase) {
    char result[WALLET_NAME_MAX_LEN + 1] = {0};
    int result_len = 0;
    char confirm_msg[DIALOG_MSG_MAX_LEN] = {0};
    int ret = 0;
    int done = 0;
    char wallet_name[48] = {0};
    uint64_t account = wallet_AccountId();
    if (!account) {
        db_error("not account");
        return -11;
    }
    // db_secure("passphrase:%s", passphrase);
    memzero(wallet_name, 40);
    if (storage_get_account_name(account, wallet_name, 32) > 0) {
        db_secure("wallet_name:%s", wallet_name);
        if (settings_set_device_name(wallet_name) < 0) {
            db_error("save wallet name:%s false", wallet_name);
            return -12;
        }

        snprintf(confirm_msg, sizeof(confirm_msg), "%s:%s", res_getLabel(LANG_LABEL_ORIGINAL_WALLET_NAME), wallet_name);
        gui_disp_info(res_getLabel(LANG_LABEL_WALLET_IS_SWITCHED), confirm_msg, TEXT_ALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK),
                     EVENT_KEY_F1);
        return 0;
    }

    do {
        ret = gui_show_edit_box(IME_ABC, IME_NUM | IME_ABC | IME_UNDERLINE, TEXT_ALIGN_CENTER,
                              res_getLabel(LANG_LABEL_INPUT_WALLET_NAME), NULL, result, 1, WALLET_NAME_MAX_LEN, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK),
                              EVENT_NONE);
        if (ret == OPER_TIMEOUT || ret == OPER_LESS_MIN || ret == KEY_EVENT_BACK) {
            continue;
        } else if (ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else if (ret < 0) {
            return ret;
        } else if (ret == OPER_OK) {
            if (is_not_empty_string(passphrase) && strcmp(result, passphrase) == 0) {
                gui_disp_info("Invalid Wallet Name", res_getLabel(LANG_LABEL_NAME_EQUAL_PASSPHRASE), TEXT_ALIGN_CENTER,
                             NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                continue;
            }
            memzero(confirm_msg, sizeof(confirm_msg));
            snprintf(confirm_msg, sizeof(confirm_msg), res_getLabel(LANG_LABEL_WALLET_NAME_CONFIRM), result);
            ret = gui_disp_info("Passphrase", confirm_msg, TEXT_ALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                               res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
            if (ret == EVENT_CANCEL) {
                continue;
            } else if (ret == EVENT_OK) {
                db_secure("wallet_name:%s", result);
                if (settings_set_device_name(result) < 0) {
                    db_error("save wallet name:%s false", result);
                    return -13;
                }
                storage_set_account_name(account, result, strlen(result));
                snprintf(confirm_msg, sizeof(confirm_msg), res_getLabel(LANG_LABEL_WALLET_SWITCHED), result);
                gui_disp_info("Passphrase", confirm_msg, TEXT_ALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK),
                             EVENT_NONE);
                done = 1;
            }
        }
        db_msg("input wallet name:%s", result);
    } while (!done);

    return 0;
}

int selectMnemonicCnt(int eventType) {
    int ret = 0;
    int count = -1;
    int supports[SUPPORT_SELECT_MNEMONIC_CNT] = {MNEMNONIC_CNT_LEVEL_24, MNEMNONIC_CNT_LEVEL_12,
                                                 MNEMNONIC_CNT_LEVEL_18};
    const char *items[SUPPORT_SELECT_MNEMONIC_CNT];
    for (int i = 0; i < SUPPORT_SELECT_MNEMONIC_CNT; ++i) {
        items[i] = gMmenCntStr[supports[i]];
    }

    ret = gui_show_menu(res_getLabel(LANG_LABEL_CHOOSE_MNEMONIC_CNT_TITLE), SUPPORT_SELECT_MNEMONIC_CNT, 0, items,
                       TEXT_ALIGN_CENTER, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                       eventType);
    if (ret == KEY_EVENT_BACK) {
        return KEY_EVENT_BACK;
    } else if (ret == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    }
    if (ret < 0) {
        db_error("select mnemonic action sheet false %d", ret);
        return ret;
    }
    if (ret >= SUPPORT_SELECT_MNEMONIC_CNT) {
        db_error("out of range for select mnemonic words");
        return -1;
    }
    count = gMmenCntVals[supports[ret]];
    db_msg("mnemonic cnt:%d ret:%d", count, ret);
    return count;
}

static int backup_device_name() {
    char name[32];
    uint64_t account = wallet_AccountId();
    if (!account) {
        db_error("not account");
        return -1;
    }
    memzero(name, sizeof(name));
    if (storage_get_account_name(account, name, sizeof(name)) > 0) {
        return 0;
    }
    memzero(name, sizeof(name));
    if (get_device_name(name, 32, 0) < 1) {
        return -1;
    }
    return storage_set_account_name(account, name, strlen(name));
}

static int check_passphrase_valid(const char *result) {
    int len = strlen(result);
    if (len < 1) {
        return -1;
    }
    if (len < 1 || len > 60) {
        return 1;
    }
    if (*result == ' ') {
        return 2;
    }
    if (*(result + len - 1) == ' ') {
        return 2;
    }
    int bn = 0;
    while (*result) {
        if (*result == ' ') {
            bn++;
            if (bn >= 2) return 3;
        } else {
            bn = 0;
        }
        result++;
    }
    return 0;
}

static int enterPassphrase(char *passphrase, int size) {
    int ret = 0;
    int done = 0;
    int input_time = 0;
    char result1[64] = {0};
    char result2[64] = {0};
    int result_len = 0;
    const char *title = NULL;
    char *result = NULL;
    char tips[128] = {0};

    do {
        if (input_time == 0) {
            result = result1;
            title = res_getLabel(LANG_LABEL_ENTER_PASSPHRASE);
        } else {
            result = result2;
            title = res_getLabel(LANG_LABEL_ENTER_CONFIRM_PASSPHRASE);
        }
        ret = gui_show_edit_box(IME_ABC, IME_NUM | IME_ABC | IME_UNDERLINE, TEXT_ALIGN_CENTER, title, NULL, result, 1, 61, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                              EVENT_KEY_F1);
        if (ret == OPER_RET) {
            return KEY_EVENT_BACK;
        } else if (ret == OPER_LESS_MIN) {
            continue;
        } else if (ret == EVENT_KEY_F1) {
            memzero(result1, sizeof(result1));
            memzero(result2, sizeof(result2));
            return RETURN_DISP_MAINPANEL;
        } else if (ret < 0) {
            return ret;
        } else if (ret == OPER_OK) {
            if (!input_time) {
                ret = check_passphrase_valid(result1);
                db_msg("check passphrase ret:%d", ret);
                if (ret) {
                    ret = dialog_l(0,
                             "Passphrase",
                             DIALOG_ICON_STYLE_NONE,
                             ret > 0 ? res_getLabel(LANG_LABEL_PASSPHRASE_INVALID_TIPS0 + ret - 1)
                                     : "Invalid Passphrase",
                             DIALOG_BUTTON_ALIGN_NONE,
                             NULL,
                             res_getLabel(LANG_LABEL_SUBMENU_OK),
                             0);
                    memzero(result2, sizeof(result2));
                    if (ret == EVENT_KEY_F1) {
                        return RETURN_DISP_MAINPANEL;
                    }
                    continue;
                }
                input_time = 1;
            } else {
                if (strlen(result1) <= 0 || strcmp(result1, result2) != 0) {
                    ret = gui_disp_info(res_getLabel(LANG_LABEL_ITEM_PASSPHRASE),
                                       res_getLabel(LANG_LABEL_INPUT_DIFFERENT),
                                       TEXT_ALIGN_CENTER | TEXT_VALIGN_CENTER, NULL,
                                       res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    input_time = 0;
                    memzero(result1, sizeof(result1));
                    memzero(result2, sizeof(result2));
                    if (ret == EVENT_KEY_F1) {
                        return RETURN_DISP_MAINPANEL;
                    }
                    continue;
                }

                memset(tips, 0x0, sizeof(tips));
                snprintf(tips, sizeof(tips), "Passphrase is \"%s\".", result);
                ret = gui_disp_info(res_getLabel(LANG_LABEL_ITEM_PASSPHRASE), tips,
                                   TEXT_ALIGN_CENTER | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                   res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                if (ret == EVENT_OK) {
                    done = 1;
                } else if (ret == EVENT_KEY_F1) {
                    memzero(result1, sizeof(result1));
                    memzero(result2, sizeof(result2));
                    return RETURN_DISP_MAINPANEL;
                } else {
                    input_time = 0;
                    memzero(result1, sizeof(result1));
                    memzero(result2, sizeof(result2));
                }
            }
        }

        ddi_sys_msleep(30);
    } while (!done);

    if (strlen(result1) > 0 && strcmp(result1, result2) == 0) {
        strlcpy(passphrase, result1, size);
        ret = 0;
    } else {
        ret = -4;
    }
    memzero(result1, sizeof(result1));
    memzero(result2, sizeof(result2));
    return ret;
}

int PassphraseGuide(void) {
    int nextIndex;
    int passwd_ok = 0;
    unsigned char passhash[PASSWD_HASHED_LEN] = {0};
    char mnenonics[MNEMONIC_MAX_LEN * MAX_MNEMONIC_CNT] = {0};
    char passphrase_val[64] = {0};
    int mlen = 0;
    int passphrase_type = -1;
    int ret = 0;
    int mChangeWin = 0;
    int have_mnemonic = get_have_mnemonic();
    uint64_t old_account_id = wallet_AccountId();
    db_msg("have_mnemonic:%d old_account_id:%llx", have_mnemonic, old_account_id);
    if (have_mnemonic < 0 || !old_account_id) {
        dialog_error3(0, -401, "Passphrase setting failed.");
        return -1;
    }
    Stack *stack = newSlack(20);
    if (!stack) {
        return -1;
    }
    pushData(stack, OP_INDEX_PASSPHRASE_TIPS);

    do {
        ret = 0;
        nextIndex = getStackTop(stack);
        db_msg("next index:%d", nextIndex);
        switch (nextIndex) {
            case OP_INDEX_PASSPHRASE_TIPS: {
                const char *item[2] = {
                        res_getLabel(LANG_LABEL_SET_PASSPHRASE),
                        res_getLabel(LANG_LABEL_WHATS_PASSPHRASE),
                };
                ret = gui_show_menu(res_getLabel(LANG_LABEL_ITEM_PASSPHRASE), 2, 0, item, TEXT_ALIGN_CENTER, NULL, NULL,
                                   EVENT_KEY_F1);
                if (ret == KEY_EVENT_BACK) {
                    nextIndex = OP_INDEX_MAX; //exit
                } else if (ret == EVENT_KEY_F1) {
                    nextIndex = OP_INDEX_MAX; //exit
                    mChangeWin = RETURN_DISP_MAINPANEL;
                } else if (ret >= 0) {
                    if (ret) {
                        pushData(stack, OP_INDEX_PASSPHRASE_DETAIL_TIPS);
                    } else {
                        pushData(stack, OP_INDEX_ACTION_DETECTION);
                    }
                }
            }
                break;
            case OP_INDEX_PASSPHRASE_DETAIL_TIPS: {
                gui_reset_cur_index();
                ret = gui_disp_info(res_getLabel(LANG_LABEL_WHATS_PASSPHRASE),
                                   res_getLabel(LANG_LABEL_WHATS_PASSPHRASE_TIPS), TEXT_ALIGN_LEFT,
                                   res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                if (ret == EVENT_CANCEL) {
                    ret = KEY_EVENT_BACK;
                    popData(stack);
                } else if (ret == EVENT_OK) {
                    pushData(stack, OP_INDEX_ACTION_DETECTION);
                } else if (ret == EVENT_KEY_F1) {
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                }
            }
                break;
            case OP_INDEX_ACTION_DETECTION:
                popData(stack);
                if (have_mnemonic) {
                    pushData(stack, OP_INDEX_SELECT_PASSPHRASE_TYPE);
                } else {
                    passphrase_type = 0;
                    pushData(stack, OP_INDEX_ENTER_PASSWD);
                }
                break;
            case OP_INDEX_SELECT_PASSPHRASE_TYPE: {
                const char *item1[2] = {
                        res_getLabel(LANG_LABEL_USE_PASSPHRASE),
                        res_getLabel(LANG_LABEL_NOT_PASSPHRASE),
                };
                ret = gui_show_menu(res_getLabel(LANG_LABEL_ITEM_PASSPHRASE), 2, 0, item1, TEXT_ALIGN_CENTER,
                                   res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                                   EVENT_KEY_F1);
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (ret < 0) {
                    break;
                } else if (ret == EVENT_KEY_F1) {
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                } else {
                    passphrase_type = ret ? 1 : 2;
                    pushData(stack, OP_INDEX_ENTER_PASSWD);
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
                } else if (ret < 0) {
                    memzero(passhash, sizeof(passhash));
                    if (ret == USER_PASSWD_ERR_VERIFY) {
                        //mChangeWin = -1;
                        nextIndex = OP_INDEX_MAX;
                    }
                    break;
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                } else {
                    backup_device_name();
                    passwd_ok = 1;
                    if (passphrase_type == 0) {
                        pushData(stack, OP_INDEX_SELECT_MNEMONIC_CNT);
                    } else if (passphrase_type == 1) {
                        memzero(passphrase_val, sizeof(passphrase_val));
                        pushData(stack, OP_INDEX_SAVE_PASSPHRASE);
                    } else {
                        pushData(stack, OP_INDEX_ENTER_PASSPHRASE);
                    }
                }
            }
                break;
            case OP_INDEX_SELECT_MNEMONIC_CNT: {
                ret = selectMnemonicCnt(EVENT_KEY_F1);
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (IS_VALID_MNEMONIC_LEN(ret)) {
                    mlen = ret;
                    pushData(stack, OP_INDEX_VERIFY_MNEMONIC_TIPS);
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                }
            }
                break;
            case OP_INDEX_VERIFY_MNEMONIC_TIPS: {
                ret = gui_disp_info("Verification", "Please enter mnemonic phrase in correct order.", TEXT_ALIGN_LEFT,
                                   res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                if (ret == EVENT_CANCEL) {
                    popData(stack);
                } else if (ret == EVENT_OK) {
                    pushData(stack, OP_INDEX_VERIFY_MNEMONIC);
                } else if (ret == EVENT_KEY_F1) {
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
                ret = enterRecoveryWord(mnenonics, MNEMONIC_MAX_LEN * mlen, mlen, passhash, 1, EVENT_KEY_F1);
                memzero(mnenonics, sizeof(mnenonics));
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (ret == 0) { //verify oK
                    have_mnemonic = 1;
                    passphrase_type = 2;
                    while (popData(stack) > 0); //clean
                    pushData(stack, OP_INDEX_PASSPHRASE_TIPS);
                    pushData(stack, OP_INDEX_ENTER_PASSPHRASE);
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                }
            }
                break;
            case OP_INDEX_ENTER_PASSPHRASE: {
                memzero(passphrase_val, sizeof(passphrase_val));
                ret = enterPassphrase(passphrase_val, sizeof(passphrase_val));
                if (ret == KEY_EVENT_BACK) {
                    memzero(passphrase_val, sizeof(passphrase_val));
                    popData(stack);
                } else if (ret < 0) {
                    memzero(passphrase_val, sizeof(passphrase_val));
                    db_error("enter passphrase failed ret:%d", ret);
                    break;
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    nextIndex = OP_INDEX_MAX;
                    mChangeWin = RETURN_DISP_MAINPANEL;
                } else {
                    pushData(stack, OP_INDEX_SAVE_PASSPHRASE);
                }
            }
                break;
            case OP_INDEX_SAVE_PASSPHRASE: {
                if ((passphrase_type == 1 && passphrase_val[0] != 0) ||
                    (passphrase_type != 1 && passphrase_val[0] == 0)) {
                    popData(stack);
                    dialog_error3(0, -403, res_getLabel(LANG_LABEL_SET_PASSPHRASE_FAILED));
                    nextIndex = OP_INDEX_MAX;
                    break;
                }
                loading_win_start(0, res_getLabel(LANG_LABEL_INIT_WALLET_ING),
                                  res_getLabel(LANG_LABEL_INIT_WALLET_TIPS), 0);
                gui_on_process(10);
                ret = wallet_store_passphrase((const unsigned char *) passphrase_val, strlen(passphrase_val), passhash);
                if (ret == 0) {
                    loading_win_refresh();
                    wallet_gen_exists_hdnode(passhash, old_account_id);
                }
                gui_on_process(100);
                loading_win_stop();
                if (ret == 0) {
                    popData(stack);
                    pushData(stack, OP_INDEX_WALLET_NAME_TIPS);
                } else {
                    popData(stack);
                    dialog_error3(0, ret, res_getLabel(LANG_LABEL_SET_PASSPHRASE_FAILED));
                    nextIndex = OP_INDEX_MAX;
                    break;
                }
            }
                break;
            case OP_INDEX_WALLET_NAME_TIPS: {
                ret = saveWalletName(passphrase_val);
                if (ret == KEY_EVENT_BACK || ret == KEY_EVENT_ABORT) {
                } else if (ret == 0 || ret == RETURN_DISP_MAINPANEL) {
                    ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
                    popData(stack);
                    mChangeWin = RETURN_DISP_MAINPANEL;
                    nextIndex = OP_INDEX_MAX;
                }
            }
                break;
            default:
                break;
        }
        set_temp_screen_time(DEFAULT_SCREEN_SAVER_TIME);
        if (nextIndex != OP_INDEX_MAX && !is_key_event_value(ret) && ret < 0) {
            dialog_error3(0, -(nextIndex * 1000) + ret, res_getLabel(LANG_LABEL_SET_PASSPHRASE_FAILED));
            nextIndex = OP_INDEX_PASSPHRASE_TIPS;
        }
    } while (nextIndex != OP_INDEX_MAX);
    memzero(passhash, sizeof(passhash));
    memzero(mnenonics, sizeof(mnenonics));
    memzero(passphrase_val, sizeof(passphrase_val));
    freeSlack(stack);

    if (mChangeWin == RETURN_DISP_MAINPANEL) {
        return RETURN_DISP_MAINPANEL;
    }

    return 0;
}
