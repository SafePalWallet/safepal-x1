#define LOG_TAG "GuideWin"

#include "wallet_util.h"
#include "GuideWin.h"
#include "debug.h"
#include "ex_types.h"
#include "global.h"
#include "bip39_english.h"
#include "Stack.h"
#include "key_event.h"
#include "passwd_util.h"
#include "gui_api.h"
#include "Passphrase.h"
#include "gui_sdk.h"
#include "settings.h"
#include "confirmseedword.h"
#include "cdrLang.h"
#include "gui_api.h"
#include "Dialog.h"
#include "secp256k1.h"
#include "resource.h"
#include "active_util.h"
#include "wallet_manager.h"
#include "wallet_util_hw.h"
#include "bip39.h"
#include "device.h"
#include "common_util.h"
#include "gui_sdk.h"
#include "gui_statusbar.h"
#include "storage_manager.h"
#include "BtprocWin.h"
#include "qr_pack.h"
#include "ex_bt.h"
#include "key_event.h"
#include "global.h"
#include "FactoryWin.h"
#include "BtRecvCode.h"
#include "gui_icons.h"
#include "SettingWin.h"
#include "dynamic_win.h"

#define ITEM_PREFIX_TXT        "%d"
#define LANG_WORD_LEN            (25)
#define MNEMO_WORD_LEN            (15)
#define ONE_PAGE_ITEM_MAX_CNT    (3)

typedef enum {
    GUIDE_INDEX_LANG = 1,
    GUIDE_DEVICE_ACTIVE_DOWNLOAD_APP_TIPS,
    GUIDE_DEVICE_ACTIVE_DOWNLOAD_APP_QR,
    GUIDE_DEVICE_ACTIVE,
    GUIDE_INDEX_GREET,
    GUIDE_INDEX_DOWNLOAD_APP_TIPS,
    GUIDE_INDEX_WALLET_NAME_TIPS,
    GUIDE_INDEX_INPUT_WALLET_NAME,
    GUIDE_INDEX_ACCOUNT_OP_SELECT,
    GUIDE_INDEX_ACCOUNT_RECOVERY,
    GUIDE_INDEX_MNEMONICS_DETAIL_TIPS,
    GUIDE_INDEX_MNEMONICS_CNT,
    GUIDE_INDEX_MNEMONICS_TIPS,
    GUIDE_INDEX_ACCOUNT_RECOVERY_TIPS,
    GUIDE_INDEX_MNEMONICS_GENERATE,
    GUIDE_INDEX_MNEMONICS_SHOW,
    GUIDE_INDEX_MNEMONICS_CONFIRM_TIPS,
    GUIDE_INDEX_MNEMONICS_CONFIRM,
    GUIDE_INDEX_MNEMONICS_CONFIRM_OK_TIPS,
    GUIDE_INDEX_PASSWD_TIPS,
    GUIDE_INDEX_ENTER_PASSWD,
    GUIDE_INDEX_KEY_INSTRUCTION,
    GUIDE_INDEX_CHECK_SECHIP,
    GUIDE_INDEX_MAX
} guideIndex;

static int getErrorCode(int code, int id) {
    return code * -1000 + id;
}

static int randomBufSize(int mlen) {
    if (!IS_VALID_MNEMONIC_LEN(mlen)) {
        db_error("mnemonic word count:%d false", mlen);
        return 0;
    }
    return (mlen * 11 - mlen / 3) / 8;
}

static int updateLang(int index) {
    if (index < 0 || index > LANG_MAXID) {
        db_error("setup lang action sheet false %d", index);
        return KEY_EVENT_BACK;
    }
    int curLang = settings_get_lang();
    int support[LANG_MAXID] = {0};
    int supportCnt = settings_get_all_langs(support);
    int newLang = support[index];
    db_msg("lang new:%d current:%d index:%d", newLang, curLang, index);
    if (newLang != curLang && IS_VALID_LANG_ID(newLang)) {
        if (settings_save(SETTING_KEY_LANGUAGE, newLang)) {
            db_msg("lang:%d save false", newLang);
            return -1;
        }
        res_updateLangAndFont(newLang);
    }
    return 0;
}

int setupLang(int param) {
    gui_clear_status_bar();

    int support[LANG_MAXID] = {0};
    const char *langs[LANG_MAXID] = {0};
    int supportCnt = settings_get_all_langs(support);
    int ret = 0;

    for (int j = 0; j < supportCnt; ++j) {
        langs[j] = res_getLangName(support[j]);
        db_msg("langs[%d]:%s", j, langs[j]);
    }
    typedef struct {
        char word[LANG_WORD_LEN];
    } Langword;
    Langword item[ONE_PAGE_ITEM_MAX_CNT];

    MENU_SET_CFG mMenu[ONE_PAGE_ITEM_MAX_CNT] = {
            {ID_NONE, VAL_OFF, SUB_OFF, NULL, NULL, 0},
            {ID_NONE, VAL_OFF, SUB_OFF, NULL, NULL, 0},
            {ID_NONE, VAL_OFF, SUB_OFF, NULL, NULL, 0},
    };

    for (int i = 0; i < ONE_PAGE_ITEM_MAX_CNT; i++) {
        memset(item[i].word, 0x0, LANG_WORD_LEN);
        snprintf(item[i].word, LANG_WORD_LEN, "%s\n", langs[i]);
        db_msg("i:%d langs:%s item[i].word:%s", i, langs[i], item[i].word);
        mMenu[i].pMenuText = item[i].word;
        mMenu[i].param = i;
    }

    int offset = 0;
    int curInx = 0;
    int max_offset = ((supportCnt - 1) / ONE_PAGE_ITEM_MAX_CNT) * ONE_PAGE_ITEM_MAX_CNT;
    while (1) {
        ret = gui_show_rich_menu_with_navi("Language",
                                           MENU_LIST | MENU_ICON_NUM | MENU_ONCE,
                                           supportCnt - offset > ONE_PAGE_ITEM_MAX_CNT ? ONE_PAGE_ITEM_MAX_CNT : supportCnt - offset, curInx, mMenu, INFO_OK,
                                           IS_VALID_LANG_ID(param) ?  INFO_BACK : "About", DIRECTION_ICON_UP_AND_DOWN,
                                           IS_VALID_LANG_ID(param) ? EVENT_KEY_F1 : EVENT_NONE);
        db_msg("gui_show_rich_menu_with_navi ret:%d", ret);
        if (ret == EVENT_NEXT_MENU) {
            db_msg("EVENT_NEXT_MENU");
            if (offset < max_offset) {
                offset = offset + ONE_PAGE_ITEM_MAX_CNT;
            } else {
                offset = 0;
            }
            curInx = 0;
        } else if (ret == EVENT_LAST_MENU) {
            db_msg("EVENT_NEXT_MENU");
            if (offset >= ONE_PAGE_ITEM_MAX_CNT) {
                offset = offset - ONE_PAGE_ITEM_MAX_CNT;
                curInx = ONE_PAGE_ITEM_MAX_CNT - 1;
            } else {
                offset = max_offset;
                curInx = supportCnt % ONE_PAGE_ITEM_MAX_CNT > 0 ? supportCnt % ONE_PAGE_ITEM_MAX_CNT - 1 : (ONE_PAGE_ITEM_MAX_CNT - 1);
                db_msg("supportCnt:%d curInx:%d", supportCnt, curInx);
            }
        } else if (ret == EVENT_CANCEL) {
            db_msg("KEY_EVENT_BACK");
            return KEY_EVENT_BACK;
        } else if (ret == RETURN_DISP_MAINPANEL || ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else if (ret <= ONE_PAGE_ITEM_MAX_CNT) {
            int inx = gui_sdk_menu_get_index();
            db_msg("KEY_EVENT_OK inx:%d  offset:%d inx+offset:%d", inx, offset, inx + offset);
            updateLang(inx + offset);

            return 0;
        } else {
            continue;
        }

        db_msg("offset:%d curInx:%d", offset, curInx);
        if (ret == EVENT_NEXT_MENU || ret == EVENT_LAST_MENU) {
            for (int i = 0; i < ONE_PAGE_ITEM_MAX_CNT; i++) {
                memset(item[i].word, 0x0, LANG_WORD_LEN);
                db_msg("i + offset:%d  supportCnt - 1:%d", i + offset, supportCnt - 1);
                if (i + offset > supportCnt - 1) {
                    mMenu[i].pMenuText = item[i].word;
                    continue;
                }
                snprintf(item[i].word, LANG_WORD_LEN, "%s\n", langs[i + offset]);
                db_msg("i:%d langs:%s item[i].word:%s", i, langs[i + offset], item[i].word);
                mMenu[i].pMenuText = item[i].word;
                mMenu[i].param = i + offset;
            }
        }

    }

    return 0;
}

static void dispActiveWaiting(void) {
    st_bt_info bt_flash_info;
    uint8_t bleName[32] = "Unknown";
    uint8_t tips[128] = {0};

    memset(&bt_flash_info, 0x0, sizeof(st_bt_info));
    ddi_flash_read(YC_INFOR_ADDR, (uint8_t *) &bt_flash_info, sizeof(bt_flash_info));
    if ((bt_flash_info.flag == BT_INFOR_FLAG) && (!is_empty_string(bt_flash_info.ble_name))) {
        memcpy(bleName, bt_flash_info.ble_name, sizeof(bt_flash_info.ble_name));
    }
    int os_version = ddi_sys_get_firmware_ver(OS_VER);
    snprintf(tips, sizeof(tips), "%s\n%s: %s\nVersion: %s-%d", res_getLabel(LANG_LABEL_BT_WAIT_CONNECT), res_getLabel(LANG_LABEL_DEVICE), bleName, DEVICE_APP_VERSION, os_version);
    gui_disp_msg(res_getLabel(LANG_LABEL_BT_CONNECT_TITLE), tips, TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK), NULL);
}

static int showDownloadAppQR(void) {
    const char url[2][32] = {"www.safepal.", "com/X1"};
    strRect txt_rect;

    gui_sdk_clear_rect(&g_gui_info.stWsRect);
    for (int i = 0; i < 2; i++) {
        txt_rect.m_x0 = 10;
        txt_rect.m_y0 = g_gui_info.uiSysIcomHeight + i * g_gui_info.uiLineHeight + 7;
        txt_rect.m_x1 = 88;
        txt_rect.m_y1 = txt_rect.m_y0 + g_gui_info.uiLineHeight - 1;
        gui_sdk_show_text(g_gui_info.stWsTextData.tType, &txt_rect, url[i]);
    }

    strRect qr_rect;
    qr_rect.m_x0 = 90;
    qr_rect.m_y0 = 20;
    qr_rect.m_x1 = qr_rect.m_x0 + 27;
    qr_rect.m_y1 = qr_rect.m_y0 + 27;
    gui_sdk_show_image(&qr_rect, gImage_x1_help);

    gui_draw_back_button();
    gui_draw_ok_button();

    ddi_lcd_brush_screen();
    
    int key = 0;
    int brush_title = 1;
    while (1) {
        ddi_key_read(&key);
        if (key == K_OK || key == K_RIGHT || key == K_OK_K3 || key == K_1 || key == K_7 || key == K_CANCEL) {
            break;
        }
        if ((brush_title == 1) || (brush_title > 20)) {
            gui_cb_check_status_bar();
            brush_title = 1;
        }
        brush_title++;

        ddi_sys_msleep(50);
    }

    if (key == K_OK || key == K_RIGHT || key == K_OK_K3) {
        return EVENT_OK;
    }
    return EVENT_CANCEL;
}

static int activeDevice(void) {
    int status = 0, notifyTick = 0;
    uint32_t key;
    uint8_t tmpbuf[600] = {0};
    uint32_t bt_status = 0, enc_state = 0, cnt = 0, brush_face = 0, brush_tip = 1;
    int ret = -1, btStatus = 0, notifyCnt = 0, recvLen = 0, brushBarCnt = 1;
    uint8_t mode = LE_PAIRING_SEC_CONNECT_NUMERIC, encStatus = 0;
    uint8_t param[8] = {0x06, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x2c, 0x01};

    ddi_bt_open();
    status = STAT_BT_INIT;

    dwin_init();
    snprintf(tmpbuf, sizeof(tmpbuf), "%s:", res_getLabel(LANG_LABEL_CONNECT_WITH_APP));
    dwin_add_txt(NULL, 0, 0, tmpbuf);
    snprintf(tmpbuf, sizeof(tmpbuf), "1. %s", res_getLabel(LANG_LABEL_OPEN_THE_APP));
    dwin_add_txt(NULL, 0, 0, tmpbuf);
    snprintf(tmpbuf, sizeof(tmpbuf), "2. %s", res_getLabel(LANG_LABEL_CONNECT_HW_WALLET));
    dwin_add_txt(NULL, 0, 0, tmpbuf);
    snprintf(tmpbuf, sizeof(tmpbuf), "3. %s", res_getLabel(LANG_LABEL_SELECT_X1));
    dwin_add_txt(NULL, 0, 0, tmpbuf);
    snprintf(tmpbuf, sizeof(tmpbuf), "4. %s", res_getLabel(LANG_LABEL_TAP_NEXT));
    dwin_add_txt(NULL, 0, 0, tmpbuf);
    snprintf(tmpbuf, sizeof(tmpbuf), "5. %s", res_getLabel(LANG_LABEL_FINISH_PAIRING));
    dwin_add_txt(NULL, 0, 0, tmpbuf);
    snprintf(tmpbuf, sizeof(tmpbuf), "6. %s", res_getLabel(LANG_LABEL_TAP_ACTIVE));
    dwin_add_txt(NULL, 0, 0, tmpbuf);
    ret = ShowWindowTxt(res_getLabel(LANG_LABEL_USER_ACTIVE_TITLE), TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK));
    dwin_destory();
    if (ret != 0 && ret != RETURN_DISP_MAINPANEL) {
        return KEY_EVENT_BACK;
    }

    ddi_bt_ioctl(DDI_BT_CTL_SET_BLE_PAIRING_MODE, (uint32_t) &mode, 0);

    while (1) {
        ddi_key_read(&key);
        if (key == K_CANCEL) {
            ddi_bt_disconnect();
            return K_CANCEL;
        }

        if (brush_face) {
            dispActiveWaiting();
            brush_face = 0;
        }

        if ((brushBarCnt == 1) || (brushBarCnt > 35)) {
            gui_cb_check_status_bar();
            brushBarCnt = 1;
        }
        brushBarCnt++;

        switch (status) {
            case STAT_BT_INIT:
                db_msg("STAT_BT_INIT");
                status = STAT_BT_START_PAIRING;
                brush_face = 1;
                Global_Ble_Process_Step = STAT_BLE_STEP_1;
                break;

            case STAT_BT_START_PAIRING:
                btStatus = ddi_bt_get_status();
                if (btStatus == BT_STATUS_CONNECTED) {
                    ret = ddi_bt_ioctl(DDI_BT_CTL_BLE_UPDATE_CONN_PARAM, (uint32_t) param, 0);
                    db_msg("update conn param ret:%d", ret);
                    status = STAT_BT_ENCRY_STATE;
                }
                break;

            case STAT_BT_ENCRY_STATE:
                ddi_bt_ioctl(DDI_BT_CTL_BLE_ENCRYPTION_STATE, 0, (uint32_t) &encStatus);
                db_msg("encStatus:%d", encStatus);
                if (encStatus == 0x01) {
                    status = STAT_DATA_RECV;
                    ddi_sys_msleep(1000);
                    ddi_sys_get_tick(&notifyTick);
                    respCommonNotify(DEVICE_READY);
                    Global_Ble_Process_Step = STAT_BLE_STEP_2;
                    notifyCnt = 0;
                    cnt = 0;
                } else {
                    cnt++;
                    if (cnt > PROC_BLE_GET_ENC_STATE_CNT) {
                        ddi_bt_ioctl(DDI_BT_CTL_BLE_START_PAIRING, 0, 0);
                        status = STAT_BT_DISP_CONFIRM_KEY;
                        cnt = 0;
                    }
                }
                break;

            case STAT_BT_DISP_CONFIRM_KEY:
                cnt = 0;
                btStatus = ddi_bt_get_status();
                if (btStatus != BT_STATUS_CONNECTED) {
                    status = STAT_BT_INIT;
                    db_msg("bt has been disconnected");
                    break;
                }
                status = dispPairCode();
                break;

            case STAT_BT_CONFIRM_KEY:
                btStatus = ddi_bt_get_status();
                if (btStatus != BT_STATUS_CONNECTED) {
                    status = STAT_BT_INIT;
                    db_msg("bt has been disconnected");
                    break;
                }
                ret = ddi_bt_ioctl(DDI_BT_CTL_BLE_CONFIRM_KEY, 0, 0);
                status = STAT_BT_GET_CONFIRM_KEY_STAT;
                gui_disp_msg(res_getLabel(LANG_LABEL_USER_ACTIVE_TITLE), res_getLabel(LANG_LABEL_CONFIRM_ACTIVATION), TEXT_ALIGN_LEFT, NULL, NULL);
                break;

            case STAT_BT_GET_CONFIRM_KEY_STAT:
                ret = ddi_bt_ioctl(DDI_BT_CTL_GET_STATUS, 0, 0);
                if (ret == BT_BNEP_BLE_PAIR) {
                    status = STAT_BT_GET_ENCRY_STATE;
                    cnt = 0;
                } else {//BT_BNEP_BLE_PAIR_FAIL
                    cnt++;
                }
                btStatus = ddi_bt_get_status();
                db_msg("ret:%d, cnt:%d, btStatus:%d", ret, cnt, btStatus);
                if (cnt > PROC_BLE_CONFIRM_PAIR_STATE_CNT || btStatus != BT_STATUS_CONNECTED) {
                    gui_disp_info(res_getLabel(LANG_LABEL_BT_CONNECT_FAIL_TITLE),
                                  res_getLabel(LANG_LABEL_BT_CONNECT_FAIL_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                  NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    status = STAT_BT_INIT;
                    cnt = 0;
                }
                break;

            case STAT_BT_GET_ENCRY_STATE:
                ddi_bt_ioctl(DDI_BT_CTL_BLE_ENCRYPTION_STATE, 0, (uint32_t) &encStatus);
                db_msg("confirm encStatus:%d", encStatus);
                if (encStatus == 0x01) {
                    status = STAT_DATA_RECV;
                    ddi_sys_get_tick(&notifyTick);
                    respCommonNotify(DEVICE_READY);
                    Global_Ble_Process_Step = STAT_BLE_STEP_2;
                    notifyCnt = 0;
                    cnt = 0;
                } else {
                    cnt++;
                    if (cnt > PROC_BLE_GET_ENC_STATE_CNT) {
                        status = STAT_DATA_RECV;
                        ddi_sys_get_tick(&notifyTick);
                        respCommonNotify(DEVICE_READY);
                        Global_Ble_Process_Step = STAT_BLE_STEP_2;
                        notifyCnt = 0;
                        cnt = 0;
                    }
                }
                break;

            case STAT_DATA_RECV:
                bt_status = ddi_bt_get_status();
                if (bt_status != BT_STATUS_CONNECTED) {
                    status = STAT_BT_INIT;
                    db_msg("bt has been disconnected");
                    break;
                }
                memset(tmpbuf, 0x0, sizeof(tmpbuf));
                recvLen = onBtRecvData(tmpbuf, sizeof(tmpbuf));
                if (recvLen > 0) {
                    db_msg("recvLen:%d", recvLen);
                    notifyCnt = PROC_BLE_NOTIFY_CNT;
                    BtRecvInit();
                    ret = onBtResult(tmpbuf, recvLen);
                    db_msg("onBtResult ret:%d", ret);
                    if (ret == WINDOWID_QRPROC) {
                        status = STAT_TRANS_PROC;
                    } else if (ret == WINDOWID_TXSHOW) {
                        status = STAT_TRANS_SIGN;
                    } else {
                        status = STAT_ERR_RSP;
                    }
                } else if (recvLen == KEY_EVENT_ABORT) {
                    brush_face = 1;
                } else {
                    if (notifyCnt < PROC_BLE_NOTIFY_CNT) {
                        if (ddi_utils_stimer_query(notifyTick, (notifyCnt + 1) * 2000)) {
                            db_msg("procResponeNotify notifyCnt:%d", notifyCnt);
                            respCommonNotify(DEVICE_READY);
                            ddi_sys_get_tick(&notifyTick);
                            notifyCnt++;
                            Global_Ble_Process_Step = STAT_BLE_STEP_2 + notifyCnt;
                        }
                    }
                }
                break;

            case STAT_TRANS_PROC:
                BtProcWin();
                status = STAT_DATA_RECV;
                break;

            case STAT_TRANS_SIGN:
                ret = procActiveDevice();
                if (ret < 0) {
                    gui_disp_info(res_getLabel(LANG_LABEL_USER_ACTIVE_TITLE), res_getLabel(LANG_LABEL_USER_ACTIVE_FAIL_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                                  EVENT_NONE);
                    ddi_bt_disconnect();
                    return -1;
                } else if (ret == DEVICE_ACTIVE_REQUEST_URL) {
                    status = STAT_DATA_RECV;
                } else if (ret == DEVICE_ACTIVE_REQUEST_DATA) {
                    ddi_bt_close();
                    gui_disp_info(res_getLabel(LANG_LABEL_USER_ACTIVE_TITLE), res_getLabel(LANG_LABEL_USER_ACTIVE_SUCCESS_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                    return 0;
                }
                break;

            default:
                status = STAT_BT_INIT;
                break;
        }

        ddi_sys_msleep(30);
    }

    return ret;
}

static int guiSaveWalletName(void) {
    char result[WALLET_NAME_MAX_LEN + 1] = {0};
    char confirm_msg[DIALOG_MSG_MAX_LEN] = {0};
    int ret = 0;
    int done = 0;

    do {
        ret = gui_show_edit_box(IME_ABC, IME_NUM | IME_ABC | IME_UNDERLINE, TEXT_ALIGN_CENTER,
                                res_getLabel(LANG_LABEL_INPUT_WALLET_NAME), NULL, result, 1, WALLET_NAME_MAX_LEN,
                                NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
        if (ret == OPER_TIMEOUT || ret == OPER_LESS_MIN || ret == KEY_EVENT_BACK) {
            continue;
        } else if (ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else if (ret < 0) {
            return ret;
        } else if (ret == 0) {
            snprintf(confirm_msg, sizeof(confirm_msg), res_getLabel(LANG_LABEL_WALLET_NAME_CONFIRM), result);
            db_msg("confirm_msg:%s", confirm_msg);
            ret = gui_disp_info(res_getLabel(LANG_LABEL_NAME_WALLET), confirm_msg, TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
            if (ret == EVENT_CANCEL) {
                continue;
            } else if (ret == EVENT_OK) {
                if (settings_set_device_name(result) < 0) {
                    db_error("save wallet name:%s false", result);
                    return -1;
                }
                storage_set_account_name(wallet_AccountId(), result, strlen(result));
                done = 1;
            }
        }
        db_msg("input wallet name:%s", result);
    } while (!done);

    return 0;
}

static int showMnemonicsWillChangeAlert(void) {
    int ret = 0;
    do {
        ret = gui_disp_info(res_getLabel(LANG_LABEL_ALERT), res_getLabel(LANG_LABEL_RE_CREAT_MNEMONIC_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                            res_getLabel(LANG_LABEL_SUBMENU_OK), 1);
        if (ret == EVENT_CANCEL) {
            return 0;
        } else if (ret < 0) {
            return ret;
        } else if (ret == EVENT_OK) {
            return KEY_EVENT_BACK;
        }
    } while (1);
    return 0;
}

static int showMnemonic(const uint16_t *mnIndexes, int mlen) {
    if (NULL == mnIndexes) {
        db_error("invalid mnIndexes:%p", mnIndexes);
        return -1;
    }

    if (mlen % 3 != 0) {
        db_error("mlen len err");
        return -2;
    }

    typedef struct {
        char word[MNEMO_WORD_LEN];
    } Mnemonicword;


    MENU_SET_CFG mMnemonicMenu[ONE_PAGE_ITEM_MAX_CNT] = {
            {ID_NONE, VAL_OFF, SUB_OFF, NULL, NULL, 0},
            {ID_NONE, VAL_OFF, SUB_OFF, NULL, NULL, 0},
            {ID_NONE, VAL_OFF, SUB_OFF, NULL, NULL, 0},
    };
    Mnemonicword item[ONE_PAGE_ITEM_MAX_CNT];

    int ret;
    const char *word = NULL;

    for (int i = 0; i < ONE_PAGE_ITEM_MAX_CNT; i++) {
        word = wordlist[mnIndexes[i]];
        memset(item[i].word, 0x0, MNEMO_WORD_LEN);
        snprintf(item[i].word, MNEMO_WORD_LEN, ITEM_PREFIX_TXT" %s\n", i + 1, word);
        db_msg("i:%d word:%s item[i].word:%s", i, word, item[i].word);
        mMnemonicMenu[i].pMenuText = item[i].word;
    }

    Global_Is_Show_Mnemonic = 1;
    Global_Is_Key_Down_End = 0;

    int offset = 0;
    int curInx = 0;
    int tempOffset = 0;
    int max_offset = ((mlen - 1) / ONE_PAGE_ITEM_MAX_CNT) * ONE_PAGE_ITEM_MAX_CNT;
    db_msg("max_offset:%d", max_offset);
    gui_reset_cur_index();
    while (1) {
        ret = gui_show_rich_menu_with_navi(res_getLabel(LANG_LABEL_WRITE_MNEMONIC_TITLE), MENU_LIST | MENU_ICON_NUM | MENU_ONCE, mlen - offset > ONE_PAGE_ITEM_MAX_CNT ? ONE_PAGE_ITEM_MAX_CNT : mlen - offset, curInx, mMnemonicMenu,
                                           Global_Is_Key_Down_End ? INFO_OK : NULL, INFO_BACK, DIRECTION_ICON_UP_AND_DOWN,
                                           EVENT_NONE);
        if (ret == EVENT_NEXT_MENU) {
            if (offset < max_offset) {
                offset = offset + ONE_PAGE_ITEM_MAX_CNT;
                curInx = 0;
            } else {
                curInx = mlen - offset - 1;
                continue;
            }
            db_msg("EVENT_NEXT_MENU: offset:%d", offset);
        } else if (ret == EVENT_LAST_MENU) {
            tempOffset = offset - ONE_PAGE_ITEM_MAX_CNT > 0 ? offset - ONE_PAGE_ITEM_MAX_CNT : 0;
            db_msg("EVENT_LAST_MENU: tempOffset%d offset:%d", tempOffset, offset);
            if (tempOffset == offset) {
                curInx = 0;
                continue;
            }
            curInx = ONE_PAGE_ITEM_MAX_CNT - 1;
            offset = tempOffset;
        } else if (ret <= ONE_PAGE_ITEM_MAX_CNT) {
            db_msg("KEY_EVENT_OK");
            Global_Is_Show_Mnemonic = 0;
            return 0;
        } else if (ret == EVENT_CANCEL) {
            db_msg("KEY_EVENT_BACK");
            Global_Is_Show_Mnemonic = 0;
            return KEY_EVENT_BACK;
        } else {
            continue;
        }

        if (ret == EVENT_NEXT_MENU || ret == EVENT_LAST_MENU) {
            db_msg("offset:%d", offset);
            for (int i = 0; i < ONE_PAGE_ITEM_MAX_CNT; i++) {
                word = wordlist[mnIndexes[i + offset]];
                memset(item[i].word, 0x0, MNEMO_WORD_LEN);
                snprintf(item[i].word, MNEMO_WORD_LEN, ITEM_PREFIX_TXT" %s\n", i + 1 + offset, word);
                db_msg("i:%d word:%s item[i].word:%s", i, word, item[i].word);
                mMnemonicMenu[i].pMenuText = item[i].word;
            }

            if (offset >= (mlen - ONE_PAGE_ITEM_MAX_CNT)) {
                Global_Is_Key_Down_End = 1;
            }
        }

    }

    Global_Is_Show_Mnemonic = 0;
    return 0;
}

static int confirmMnemonic(const uint16_t *mnIndexes, int mlen) {
    if (!mnIndexes || mlen <= 0) {
        db_error("invalid paras  indexes:%p, mlen:%d", mnIndexes, mlen);
        return -1;
    }

    int ret = 0;
    ConfirmSeedWordConfig_t config;
    memset(&config, 0x0, sizeof(ConfirmSeedWordConfig_t));
    config.seedWordCnt = mlen;
    config.seeds = mnIndexes;

    ret = showConfirmSeedWord(&config);

    return ret;
}

static int enterPassword(unsigned char passhash[PASSWD_HASHED_LEN]) {
    if (!passhash) {
        db_error("invalid paras passhash:%p", passhash);
        return -1;
    }

    memzero(passhash, PASSWD_HASHED_LEN);
    unsigned char new_passhash[PASSWD_HASHED_LEN];
    int ret = 0;
    int done = 0;
    int step = 0; // enter passwd again

    do {
        memzero(passhash, PASSWD_HASHED_LEN);
        memzero(new_passhash, PASSWD_HASHED_LEN);
        ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_SET_PIN_TITLE), PIN_CODE_CHECK, passhash, 0);
        //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        if (ret == KEY_EVENT_ABORT) {
            memzero(passhash, PASSWD_HASHED_LEN);
            memzero(new_passhash, PASSWD_HASHED_LEN);
            return USER_PASSWD_ERR_ABORT;
        }
        if (ret == USER_PASSWD_ERR_FORMAT || ret == USER_PASSWD_ERR_WEAK || ret == USER_PASSWD_ERR_NOT_INPUT ||
            ret == RETURN_DISP_MAINPANEL) {
            continue;
        }
        if (ret < 0) {
            db_error("set passwd false ret:%d", ret);
            memzero(passhash, PASSWD_HASHED_LEN);
            memzero(new_passhash, PASSWD_HASHED_LEN);
            return ret;
        }
        step = 1;
        do {
            ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_CONFIRM_PASSWD), PIN_CODE_NONE, new_passhash, 0);
            //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
            if (ret == KEY_EVENT_ABORT) {
                memzero(passhash, PASSWD_HASHED_LEN);
                memzero(new_passhash, PASSWD_HASHED_LEN);
                return KEY_EVENT_ABORT;
            }
            if (ret == USER_PASSWD_ERR_FORMAT || ret == USER_PASSWD_ERR_WEAK) {
                step = 0;
                break;
            }
            if (ret == USER_PASSWD_ERR_NOT_INPUT || ret == RETURN_DISP_MAINPANEL) {
                continue;
            }
            if (ret < 0) {
                db_error("confirm passwd false ret:%d", ret);
                memzero(passhash, PASSWD_HASHED_LEN);
                memzero(new_passhash, PASSWD_HASHED_LEN);
                return ret;
            }
            if (ret == USER_PASSWD_ERR_NONE) {
                break;
            }
        } while (1);

        if (!step) {
            continue;
        }
        if (memcmp(passhash, new_passhash, PASSWD_HASHED_LEN) != 0) {
            db_error("passswd hash compare false");
            gui_disp_info(res_getLabel(LANG_LABEL_PASSWD_ERROR_TITLE), res_getLabel(LANG_LABEL_CHANGE_PIN_FAIL_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL,
                          res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
            continue;
        } else {
            done = 1;
        }
    } while (!done);
    memzero(new_passhash, PASSWD_HASHED_LEN);
    return 0;
}

static int generateMnemonic(uint16_t *mnIndexes, int mlen, unsigned char *randomBuf) {
    int ret = 0;
    int random_sz = randomBufSize(mlen);
    unsigned char tmpbuf[MAX_MNEMONIC_BUFFSIZE] = {0};
    uint16_t tmpIndex[24] = {0};

    if (NULL == mnIndexes || NULL == randomBuf) {
        db_error("invalid mnIndexes:%p randomBuf:%p", mnIndexes, randomBuf);
        return -1;
    }
    if (!IS_VALID_MNEMONIC_LEN(mlen)) {
        db_error("mnemonic cnt:%d false", mlen);
        return -2;
    }
    ret = get_mix_random_buffer(tmpbuf, random_sz);
    if (ret != random_sz) {
        db_error("get random failed ret:%d", ret);
        memzero(tmpbuf, sizeof(tmpbuf));
        return -3;
    }
    ret = mnemonic_index_from_data(tmpbuf, random_sz, tmpIndex);
    if (ret != mlen) {
        db_error("get random index failed ret:%d", ret);
        memzero(tmpbuf, sizeof(tmpbuf));
        memzero(tmpIndex, sizeof(tmpIndex));
        return -4;
    }

    memcpy(mnIndexes, tmpIndex, sizeof(uint16_t) * mlen);
    memcpy(randomBuf, tmpbuf, random_sz);

    memzero(tmpbuf, sizeof(tmpbuf));
    memzero(tmpIndex, sizeof(tmpIndex));

    return 0;
}

static int check_mnemonic_match(const unsigned char *passwd, const char *mnemonic, const char *passphrase) {
    uint8_t seed[512 / 8] = {0};
    mnemonic_to_seed(mnemonic, passphrase, seed, NULL);
    HDNode node[1];
    memset(node, 0, sizeof(HDNode));
    hdnode_gen_from_seed(seed, 512 / 8, &secp256k1_info, node);
    hdnode_private_ckd_prime(node, 44);
    hdnode_private_ckd_prime(node, 0);
    hdnode_private_ckd_prime(node, 0);
    hdnode_fill_public_key(node);
    db_secure("chaincode1:%s %s", passphrase, debug_ubin_to_hex(node->chain_code, 32));
    db_secure("public_key1:%s %s", passphrase, debug_ubin_to_hex(node->public_key, 33));

    PubHDNode node2;
    int ret = wallet_queryPubHDNode(CURVE_SECP256K1, "m/44h/0h/0h", passwd, &node2);
    if (ret != 0) {
        db_error("query BTC PubHDNode false");
        return ret;
    }
    if (memcmp(node->chain_code, node2.chain_code, 32) != 0) {
        db_error("ummatch chaincode:%s", debug_ubin_to_hex(node2.chain_code, 32));
        return 1;
    }
    if (memcmp(node->public_key, node2.public_key, 33) != 0) {
        db_error("ummatch public_key:%s", debug_ubin_to_hex(node2.public_key, 33));
        return 1;
    }
    return 0;
}

static int guideEnterPassphrase(char *passphrase, int size) {
    char result[64] = {0};
    int ret = 0;
    int done = 0;

    do {
        ret = gui_show_edit_box(IME_ABC, IME_NUM | IME_ABC | IME_UNDERLINE, TEXT_ALIGN_CENTER,
                                res_getLabel(LANG_LABEL_ENTER_PASSPHRASE), NULL, result, 1, 61, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
        if (ret == OPER_RET) {
            return KEY_EVENT_BACK;
        } else if (ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else if (ret == OPER_LESS_MIN) {
            continue;
        } else if (ret < 0) {
            return ret;
        } else if (ret == OPER_OK) {
            done = 1;
        } else if (ret == EVENT_KEY_F1) {
            memzero(result, sizeof(result));
            return EVENT_KEY_F1;
        }
        ddi_sys_msleep(30);
    } while (!done);

    if (strlen(result) > 0) {
        strlcpy(passphrase, result, size);
        ret = 0;
    } else {
        ret = -4;
    }
    memzero(result, sizeof(result));

    return ret;
}

static int clean_data() {
    db_msg("clean all data");
    loading_win_start(0, "", NULL, 0);
    storage_cleanAllData();
    loading_win_refresh();
    doFactoryReset();
    loading_win_refresh();
    //int ret = device_reformat_data_partition();
    //db_msg("reformat data ret:%d", ret);
    loading_win_stop();
    if (gSettings->mLang != 0) {
        settings_save(SETTING_KEY_LANGUAGE, settings_get_lang());
    }
    return 0;
}

//flag:0 guide gen wallet 
//flag:1 verify need passhash
int enterRecoveryWord(char *mnemonics, int size, int mlen, const unsigned char *passwd, char flag, int eventType) {
    if (NULL == mnemonics || size <= 0) {
        db_error("invalid paras mnemonics:%p, size:%d", mnemonics, size);
        return -1;
    }
    if (!IS_VALID_MNEMONIC_LEN(mlen)) {
        db_error("mnemonic word count:%d false", mlen);
        return -1;
    }
    db_secure("size:%d mlen:%d", size, mlen);
    int index = 0;
    int ret = 0;
    int err = 0;
    int checked_word = 0;
    char title[DIALOG_TITLE_MAX_LEN] = {0};
    char kb_result[MNEMONIC_MAX_LEN] = {0};
    char srcMnemonics[MNEMONIC_MAX_LEN * MAX_MNEMONIC_CNT] = {0};
    char passphrase_val[64] = {0};
    int sz = size;
    int offset = 0;
    int strLen = 0;
    int isBack = 0;

    index = 0;
    memzero(mnemonics, sz);
    do {
        memcpy(kb_result, srcMnemonics + index * MNEMONIC_MAX_LEN, MNEMONIC_MAX_LEN);
        db_secure("mnemonics index:%d str:%s", index, srcMnemonics + index * MNEMONIC_MAX_LEN);
        snprintf(title, sizeof(title), res_getLabel(LANG_LABEL_ENTER_MNEMONIC), index + 1);
        db_secure("keyboard init result:%s", kb_result);

        ret = gui_show_edit_box(IME_ASSOC, IME_ABC_SMALL, TEXT_ALIGN_CENTER, title, NULL, kb_result, 3, 12, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), eventType);
        db_msg("ret:%d", ret);
        if (ret == KEY_EVENT_BACK) {
            if (index <= 0) {
                isBack = 1;
                break;
            }
            int kb_result_len = strlen(kb_result);
            if (kb_result_len == 0) {
                memzero(srcMnemonics + index * MNEMONIC_MAX_LEN, MNEMONIC_MAX_LEN);
            }
            index--;
            continue;
        } else if (ret < 0) {
            err = 1;
            break;
        } else if (ret == 0) {
            //input ok
            db_secure("enter mnemonic:%s ret:%d", kb_result, ret);
        } else if (ret == EVENT_KEY_F1) {
            err = RETURN_DISP_MAINPANEL;
            break;
        }
        memzero(srcMnemonics + index * MNEMONIC_MAX_LEN, MNEMONIC_MAX_LEN);
        memcpy(srcMnemonics + index * MNEMONIC_MAX_LEN, kb_result, strlen(kb_result));
        if (index < (mlen - 1)) {
            index++;
        } else {
            memzero(mnemonics, sz);
            offset = 0;
            int i;
            for (i = 0; i < mlen; ++i) {
                strLen = strlen(srcMnemonics + i * MNEMONIC_MAX_LEN);
                if (!strLen) {
                    break;
                }
                memcpy(mnemonics + offset, (srcMnemonics + i * MNEMONIC_MAX_LEN), strLen);
                offset += strLen;
                if (i < (mlen - 1)) {
                    memcpy(mnemonics + offset, " ", 1);
                    offset++;
                }
            }
            *(mnemonics + offset) = '\0';
            db_secure("mnemonics cat str:%s", mnemonics);
            if (i != mlen) { //count error?
                db_serr("have empty word? mlen:%d i:%d", mlen, i);
                err = 1;
                break;
            }
            ret = mnemonic_check(mnemonics);
            db_secure("mnemonic check ret:%d", ret);
            if (!ret) {
                ret = dialog(0, res_getLabel(LANG_LABEL_INVALID_MNEMONIC), DIALOG_ICON_STYLE_ERR, res_getLabel(LANG_LABEL_INVALID_MNEMONIC_SPELLING),
                             DIALOG_BUTTON_ALIGN_CENTER, NULL, NULL, 0);
                if (ret == EVENT_CANCEL) {
                    index = mlen - 1;
                } else if (ret < 0) {
                    err = 1;
                    break;
                } else {
                }
            } else {
                if (flag == 0) {
                    checked_word = 1;
                    break;
                } else if (flag == 1) {
                    memset(passphrase_val, 0, sizeof(passphrase_val));
                    int verify_ret = check_mnemonic_match(passwd, mnemonics, "");
                    db_secure("verify mnemonic ret:%d", verify_ret);
                    if (verify_ret == 1) {
                        ret = gui_disp_info(res_getLabel(LANG_LABEL_ITEM_VERIFY),
                                            res_getLabel(LANG_LABEL_VERIFY_FAIL_ASK),
                                            TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                            res_getLabel(LANG_LABEL_SUBMENU_OK), eventType);
                        if (ret == EVENT_OK) {
                            int pret = guideEnterPassphrase(passphrase_val, sizeof(passphrase_val));
                            if (pret == KEY_EVENT_BACK) {
                                //lastKey = KEY_EVENT_BACK;
                                continue;
                            } else if (pret == RETURN_DISP_MAINPANEL) {
                                err = RETURN_DISP_MAINPANEL;
                                break;
                            }

                            if (pret == 0) {
                                verify_ret = check_mnemonic_match(passwd, mnemonics, passphrase_val);
                                db_secure("verify mnemonic passphrase ret:%d", verify_ret);
                            }
                        } else if (ret == EVENT_CANCEL) {
                            continue;
                        } else if (ret == EVENT_KEY_F1) {
                            err = RETURN_DISP_MAINPANEL;
                            break;
                        }
                    }
                    if (verify_ret != 0) {
                        if (verify_ret == 1) {
                            ret = gui_disp_info(res_getLabel(LANG_LABEL_INVALID_MNEMONIC),
                                                passphrase_val[0] ? res_getLabel(LANG_LABEL_VERIFY_PASSPHRASE_FAIL)
                                                                  : res_getLabel(LANG_LABEL_CHECK_MNEMONIC),
                                                TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                                res_getLabel(LANG_LABEL_SUBMENU_OK), eventType);
                            if (ret == EVENT_KEY_F1) {
                                err = RETURN_DISP_MAINPANEL;
                                break;
                            }
                            const char *item[2] = {
                                    res_getLabel(LANG_LABEL_TRY_AGAIN),
                                    res_getLabel(LANG_LABEL_TX_EXIT),
                            };
                            ret = gui_show_menu(res_getLabel(LANG_LABEL_VERIFY_FAIL_TIPS), 2, 0, item, TEXT_ALIGN_CENTER,
                                                NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), eventType);
                            if (ret == 1) {
                                err = 88;
                                break;
                            } else if (ret == EVENT_KEY_F1) {
                                err = RETURN_DISP_MAINPANEL;
                                break;
                            }
                        } else {
                            dialog_error3(0, verify_ret, "Seed verify failed.");
                        }
                    } else {
                        ret = gui_disp_info(res_getLabel(LANG_LABEL_ITEM_VERIFY),
                                            passphrase_val[0] ? res_getLabel(LANG_LABEL_VERIFY_PASSPHRASE_SUCCESS)
                                                              : res_getLabel(LANG_LABEL_VERIFY_SUCCESS),
                                            TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                            res_getLabel(LANG_LABEL_SUBMENU_OK), eventType);
                        if (ret == EVENT_KEY_F1) {
                            err = RETURN_DISP_MAINPANEL;
                            break;
                        }
                        checked_word = 1;
                        break;
                    }
                }
            }
        }
    } while (1);
    memzero(kb_result, sizeof(kb_result));
    memzero(srcMnemonics, sizeof(srcMnemonics));
    memzero(passphrase_val, sizeof(passphrase_val));
    if (err) {
        memzero(mnemonics, sz);
        return -1;
    }
    if (isBack) {
        memzero(mnemonics, sz);
        return KEY_EVENT_BACK;
    }
    if (!checked_word) {
        memzero(mnemonics, sz);
        return -1;
    }
    return 0;
}

static int showAboutWalletSimple(void) {
    char str[128], sn[24];
    int ret = 0, os_version;
    int width = 0;

    dwin_init();

    //version
    os_version = ddi_sys_get_firmware_ver(OS_VER);
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s: %s-%d", res_getLabel(LANG_LABEL_FIRMWARE_VERSION), DEVICE_APP_VERSION, os_version);
    width = ddi_lcd_get_text_width(str);
    if (width > g_gui_info.uiScrWidth) {
        snprintf(str, sizeof(str), "%s:\n%s-%d", res_getLabel(LANG_LABEL_FIRMWARE_VERSION), DEVICE_APP_VERSION, os_version);
    }
    SetWindowMText(0, str);

    //sn
    memset(sn, 0x0, sizeof(sn));
    device_get_sn(sn, 24);
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s: %s", res_getLabel(LANG_LABEL_DEVICE_SN), sn);
    width = ddi_lcd_get_text_width(str);
    if (width > g_gui_info.uiScrWidth) {
        snprintf(str, sizeof(str), "%s:\n%s", res_getLabel(LANG_LABEL_DEVICE_SN), sn);
    }
    SetWindowMText(0, str);

    ret = ShowWindowTxt(res_getLabel(LANG_LABEL_SET_ITEM_ABOUT), TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK));
    dwin_destory();

    return ret;
}

int startGuide(void) {
    db_msg("startGuide");
    int nextIndex = GUIDE_INDEX_LANG;
    uint16_t mIndexes[MAX_MNEMONIC_CNT] = {0};
    unsigned char randomBuf[MAX_MNEMONIC_BUFFSIZE] = {0};
    char mnenonics[MNEMONIC_MAX_LEN * MAX_MNEMONIC_CNT] = {0};
    char tmpbuf[256];
    int mlen = 0;
    int recovery_flag = 0;
    int ret = 0;
    int guideDone = 0;

    Stack *stack = newSlack(20);
    if (!stack) {
        db_error("newSlack error!!!");
        return -1;
    }
    pushData(stack, GUIDE_INDEX_LANG);
    Global_Guide_abort = 0;
    do {
        ret = 0;
        nextIndex = getStackTop(stack);

        switch (nextIndex) {
            case GUIDE_INDEX_LANG: {
                ret = setupLang(LANG_SHOW_ABOUT_WITH_BACK_ICON);
                if (Global_Guide_abort) {
                    db_error("Global_Guide_abort goto setting");
                    //changeWindow(WINDOWID_SETTING);
                    return 0;
                }
                if (ret == 0) {
                    if (device_get_active_time() == 0) {
                        pushData(stack, GUIDE_DEVICE_ACTIVE_DOWNLOAD_APP_TIPS);
                    } else {
                        pushData(stack, GUIDE_INDEX_GREET);
                    }
                } else if (ret == KEY_EVENT_BACK) {
                    showAboutWalletSimple();
                }
            }
                break;
            case GUIDE_DEVICE_ACTIVE_DOWNLOAD_APP_TIPS: {
                ret = gui_disp_info(res_getLabel(LANG_LABEL_USER_ACTIVE_TITLE), res_getLabel(LANG_LABEL_ACTIVATE_DOWNLOAD_APP_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                    res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == EVENT_CANCEL) {
                    ret = KEY_EVENT_BACK;
                    popData(stack);
                } else if (ret == EVENT_OK) {
                    pushData(stack, GUIDE_DEVICE_ACTIVE_DOWNLOAD_APP_QR);
                }
            }
                break;
            case GUIDE_DEVICE_ACTIVE_DOWNLOAD_APP_QR: {
                ret = showDownloadAppQR();
                if (ret != EVENT_OK) {
                    popData(stack);
                } else {
                    pushData(stack, GUIDE_DEVICE_ACTIVE);
                }
            }
                break;
            case GUIDE_DEVICE_ACTIVE: {
                if (device_get_active_time() == 0) {
                    ret = activeDevice();
                    if (ret == 0) {
                        pushData(stack, GUIDE_INDEX_GREET);
                    } else if (ret == 1) { //jump qr
                        db_error("jump to qr scan,break");
                        return 0;
                    } else if (ret == K_CANCEL || ret == -1) {
                        continue;
                    } else if (ret == KEY_EVENT_BACK) {
                        popData(stack);
                    }
                } else {
                    pushData(stack, GUIDE_INDEX_GREET);
                }
            }
                break;
            case GUIDE_INDEX_GREET: {
                ret = gui_disp_info("SafePal X1", res_getLabel(LANG_LABEL_GUIDE_GREET), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                    res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == EVENT_CANCEL) {
                    ret = KEY_EVENT_BACK;
                    // popData(stack);
                    pushData(stack, GUIDE_INDEX_LANG);
                } else if (ret == EVENT_OK) {
                    pushData(stack, GUIDE_INDEX_ACCOUNT_OP_SELECT);
                }
            }
                break;
            case GUIDE_INDEX_ACCOUNT_OP_SELECT: {
                const char *item[] = {
                        res_getLabel(LANG_LABEL_CREATE_ACCOUNT),
                        res_getLabel(LANG_LABEL_RECOVERY_ACCOUNT),
                };
                ret = gui_show_menu(res_getLabel(LANG_LABEL_ADD_WALLET_TITLE), 2, 0, item, TEXT_ALIGN_CENTER,
                                    res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == KEY_EVENT_BACK) {
                    ret = KEY_EVENT_BACK;
                    popData(stack);
                } else if (ret < 0) {
                    break;
                } else {
                    recovery_flag = ret ? 1 : 0;
                    pushData(stack, recovery_flag ? GUIDE_INDEX_MNEMONICS_CNT : GUIDE_INDEX_MNEMONICS_TIPS);
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_TIPS: {
                const char *item_tips[] = {
                        res_getLabel(LANG_LABEL_CREATE_NOW),
                        res_getLabel(LANG_LABEL_MNEMONIC_IS_WHAT),
                };
                ret = gui_show_menu(res_getLabel(LANG_LABEL_CREATE_WALLET_TITLE), 2, 0, item_tips, TEXT_ALIGN_CENTER,
                                    res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == KEY_EVENT_BACK) {
                    ret = KEY_EVENT_BACK;
                    popData(stack);
                } else if (ret < 0) {
                    break;
                } else {
                    pushData(stack, ret ? GUIDE_INDEX_MNEMONICS_DETAIL_TIPS : GUIDE_INDEX_MNEMONICS_CNT);
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_DETAIL_TIPS: {
                ret = gui_disp_info(res_getLabel(LANG_LABEL_MNEMONIC_IS_WHAT),
                                    res_getLabel(LANG_LABEL_MNEMONIC_IS_WHAT_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                    res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == EVENT_CANCEL) {
                    ret = KEY_EVENT_BACK;
                    popData(stack);
                } else if (ret == EVENT_OK) {
                    pushData(stack, GUIDE_INDEX_MNEMONICS_CNT);
                } else {
                    break;
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_CNT: {
                ret = selectMnemonicCnt(EVENT_NONE);
                db_msg("selectMnemonicCnt ret=%d", ret);
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (ret > 0) {
                    memzero(mIndexes, sizeof(mIndexes));
                    memzero(randomBuf, sizeof(randomBuf));
                    memzero(mnenonics, sizeof(mnenonics));
                    mlen = ret;
                    if (device_get_hw_break_state(3) != 0) {
                        dialog_error3(0, -801, "The device is broken, please contact the SafePal team for help.");
                        break;
                    }
                    if (!device_is_inited()) {
                        dialog_error3(0, -802, "Init failed.");
                        break;
                    }
                    if (clean_data() != 0) {
                        dialog_error3(0, -803, "Init failed.");
                        break;
                    }
                    pushData(stack, GUIDE_INDEX_CHECK_SECHIP);
                } else {
                    break;
                }
            }
                break;
            case GUIDE_INDEX_CHECK_SECHIP: {
                popData(stack);
                ret = 0;//checkSechip(0);
                if (ret != 0) {
                    db_error("check sechip false ret:%d", ret);
                    ret = 0;//force reset ret
                } else {
                    db_msg("check sechip OK");
                    pushData(stack, recovery_flag ? GUIDE_INDEX_ACCOUNT_RECOVERY : GUIDE_INDEX_MNEMONICS_GENERATE);
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_GENERATE: {
                if (!IS_VALID_MNEMONIC_LEN(mlen)) {
                    break;
                }
                memzero(mIndexes, sizeof(mIndexes));
                memzero(randomBuf, sizeof(randomBuf));
                memzero(mnenonics, sizeof(mnenonics));
                ret = generateMnemonic(mIndexes, mlen, randomBuf);
                if (ret < 0) {
                    break;
                } else if (ret == 0) {
                    popData(stack);
                    pushData(stack, GUIDE_INDEX_MNEMONICS_SHOW);
                    settings_save(SETTING_KEY_ACCOUNT_TYPE, ACCOUNT_TYPE_NEW_GEN);
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_SHOW: {
                set_temp_screen_time(DEFAULT_HI_SCREEN_SAVER_TIME);
                if (!IS_VALID_MNEMONIC_LEN(mlen)) {
                    break;
                }
                ret = showMnemonic(mIndexes, mlen);
                if (ret == KEY_EVENT_BACK) {
                    ret = showMnemonicsWillChangeAlert();
                    if (ret == KEY_EVENT_BACK) {
                        popData(stack);
                    } else if (ret < 0) {
                        break;
                    }
                } else if (ret < 0) {
                    break;
                } else {
                    pushData(stack, GUIDE_INDEX_MNEMONICS_CONFIRM_TIPS);
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_CONFIRM_TIPS: {
                set_temp_screen_time(DEFAULT_HI_SCREEN_SAVER_TIME);
                ret = gui_disp_info(res_getLabel(LANG_LABEL_MNEMONIC_VERIFY_TITLE),
                                    res_getLabel(LANG_LABEL_MNEMONIC_VERIFY_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                    res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == EVENT_CANCEL) {
                    ret = KEY_EVENT_BACK;
                    popData(stack);
                } else if (ret == EVENT_OK) {
                    pushData(stack, GUIDE_INDEX_MNEMONICS_CONFIRM);
                } else {
                    break;
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_CONFIRM: {
                set_temp_screen_time(DEFAULT_HI_SCREEN_SAVER_TIME);
                if (!IS_VALID_MNEMONIC_LEN(mlen)) {
                    break;
                }
                ret = confirmMnemonic(mIndexes, mlen);
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (ret < 0) {
                    db_error("confirm menemonic error ret:%d", ret);
                    break;
                } else {
                    pushData(stack, GUIDE_INDEX_MNEMONICS_CONFIRM_OK_TIPS);
                }
            }
                break;
            case GUIDE_INDEX_MNEMONICS_CONFIRM_OK_TIPS: {
                set_temp_screen_time(DEFAULT_HI_SCREEN_SAVER_TIME);
                ret = gui_disp_info(res_getLabel(LANG_LABEL_MNEMONICS_CONFIRM_OK_TITLE),
                                    res_getLabel(LANG_LABEL_MNEMONICS_CONFIRM_OK_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                    res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == EVENT_CANCEL) {
                    ret = gui_disp_info(res_getLabel(LANG_LABEL_ALERT), res_getLabel(LANG_LABEL_RE_VERIFY_MNEMONIC_TIPS),
                                        TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                        res_getLabel(LANG_LABEL_BACK),
                                        res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                    if (ret == EVENT_OK) {
                        popData(stack);
                    }
                } else if (ret == EVENT_OK) {
                    pushData(stack, GUIDE_INDEX_PASSWD_TIPS);
                } else {
                    db_error("show dialog passwd tips error ret:%d", ret);
                    break;
                }
            }
                break;
            case GUIDE_INDEX_PASSWD_TIPS: {
                set_temp_screen_time(DEFAULT_HI_SCREEN_SAVER_TIME);
                ret = gui_disp_info(res_getLabel(LANG_LABEL_SET_PIN_TITLE), res_getLabel(LANG_LABEL_SET_PIN_TIPS),
                                    TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                    res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                if (ret == EVENT_CANCEL) {
                    popData(stack);
                } else if (ret == EVENT_OK) {
                    pushData(stack, GUIDE_INDEX_ENTER_PASSWD);
                } else {
                    db_error("show dialog passwd tips error ret:%d", ret);
                    break;
                }
            }
                break;
            case GUIDE_INDEX_ENTER_PASSWD: {
                set_temp_screen_time(DEFAULT_HI_SCREEN_SAVER_TIME);
                if (!IS_VALID_MNEMONIC_LEN(mlen)) {
                    break;
                }
                ret = sec_reset_randkey(1);
                if (ret != 0) {
                    break;
                }
                unsigned char passhash[PASSWD_HASHED_LEN] = {0};
                unsigned char seedbin[96] = {0};
                ret = enterPassword(passhash);
                if (ret == KEY_EVENT_ABORT) {
                    popData(stack);
                } else if (ret < 0) {
                    memzero(passhash, sizeof(passhash));
                    break;
                } else {
                    if (recovery_flag) {
                    } else {
                        if (buffer_is_zero(randomBuf, randomBufSize(mlen))) {
                            db_serr("random is zero");
                            break;
                        }
                        memzero(mnenonics, sizeof(mnenonics));
                        if (mnemonic_words_from_data(randomBuf, randomBufSize(mlen), mnenonics) != mlen) {
                            db_serr("invalid random");
                            break;
                        }
                    }
                    gui_show_state(res_getLabel(LANG_LABEL_INIT_WALLET_ING), res_getLabel(LANG_LABEL_INIT_WALLET_TIPS));
                    if (mnenonics[0] == 0) {
                        db_secure("empty Mnemonics");
                        break;
                    }
                    if (!mnemonic_check(mnenonics)) {
                        break;
                    }
                    gui_on_process(10);
                    memzero(seedbin, sizeof(seedbin));
                    mnemonic_to_seed(mnenonics, "", seedbin, NULL);
                    gui_on_process(20);
                    ret = wallet_storeSeed(seedbin, 64, passhash);
                    gui_on_process(70);
                    db_secure("save seed ret:%d", ret);
                    if (ret == 0) {
                        ret = wallet_verify_mnemonic((const unsigned char *) mnenonics, strlen(mnenonics), passhash);
                        db_secure("verify mnemonic ret:%d", ret);
                        if (ret != 0) {
                            ret = -500 + ret;
                            settings_set_have_seed(0);
                        }
                    }
                    gui_on_process(90);
                    if (ret == 0) {
                        ret = wallet_verify_seed_xpub(seedbin, 64);
                        db_secure("verify seed xpub ret:%d", ret);
                        if (ret != 0) {
                            ret = -600 + ret;
                            settings_set_have_seed(0);
                        }
                    }
                    memzero(passhash, sizeof(passhash));
                    memzero(seedbin, sizeof(seedbin));
                    gui_on_process(100);
                    if (ret) {
                        break;
                    } else {
                        GLobal_PIN_Passed = 1;
                        pushData(stack, GUIDE_INDEX_INPUT_WALLET_NAME);
                    }
                }
            }
                break;
            case GUIDE_INDEX_INPUT_WALLET_NAME: {
                ret = guiSaveWalletName();
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (ret < 0) {
                    db_error("input wallet name failed ret:%d", ret);
                    break;
                } else {
                    pushData(stack, GUIDE_INDEX_DOWNLOAD_APP_TIPS);
                }
            }
                break;
            case GUIDE_INDEX_DOWNLOAD_APP_TIPS: {
                gui_disp_info(res_getLabel(LANG_LABEL_DOWNLOAD_APP_TITLE), res_getLabel(LANG_LABEL_DOWNLOAD_APP_TIPS),
                              TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                nextIndex = GUIDE_INDEX_MAX;
                guideDone = 1;
            }
                break;
            case GUIDE_INDEX_ACCOUNT_RECOVERY: {
                if (!IS_VALID_MNEMONIC_LEN(mlen)) {
                    db_error("invalid mlen:%d", mlen);
                    break;
                }
                int size = MNEMONIC_MAX_LEN * mlen;
                memzero(mIndexes, sizeof(mIndexes));
                memzero(randomBuf, sizeof(randomBuf));
                memzero(mnenonics, sizeof(mnenonics));
                ret = enterRecoveryWord(mnenonics, size, mlen, NULL, 0, EVENT_NONE);
                db_msg("enterRecoveryWord ret:%d", ret);
                if (ret == KEY_EVENT_BACK) {
                    popData(stack);
                } else if (ret < 0) {
                    memzero(mnenonics, size);
                    db_error("recovery account failed!");
                    break;
                } else if (ret == 0) { //force check == 0
                    pushData(stack, GUIDE_INDEX_PASSWD_TIPS);
                    settings_save(SETTING_KEY_ACCOUNT_TYPE, ACCOUNT_TYPE_RECOVERY);
                }
            }
                break;
            default:
                break;
        }

        set_temp_screen_time(DEFAULT_SCREEN_SAVER_TIME);
        if (!is_key_event_value(ret) && ret < 0) {
            const char *format = (res_getLabel(LANG_LABEL_WALLET_INIT_FAILED_TIPS));
            int code = getErrorCode(nextIndex, ret);
            snprintf(tmpbuf, sizeof(tmpbuf), format, code);
            dialog_error2(0, tmpbuf, res_getLabel(LANG_LABEL_TRY_AGAIN));
            nextIndex = GUIDE_INDEX_LANG;
//            pushData(stack, nextIndex);
        }

        ddi_sys_msleep(100);
    } while (nextIndex != GUIDE_INDEX_MAX);

    memzero(mIndexes, sizeof(mIndexes));
    memzero(randomBuf, sizeof(randomBuf));
    memzero(mnenonics, sizeof(mnenonics));

    freeSlack(stack);
    if (guideDone) {
        //changeWindow(WINDOWID_MAINPANEL);
    }

    db_msg("guide is return");

    return 0;
}
