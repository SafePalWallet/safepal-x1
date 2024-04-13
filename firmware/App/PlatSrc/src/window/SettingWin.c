#include "ex_types.h"
#include "debug.h"
#include "gui_sdk.h"
#include "SettingWin.h"
#include "cdrLang.h"
#include "GuideWin.h"
#include "CoinsWin.h"
#include "gui_api.h"
#include "VerifyWin.h"
#include "passwd_util.h"
#include "Passphrase.h"
#include "resource.h"
#include "wallet_manager.h"
#include "FactoryWin.h"
#include "device.h"
#include "Dialog.h"
#include "secure_api.h"
#include "ex_bt.h"
#include "dynamic_win.h"
#include "update.h"
#include "cmaths.h"
#include "gui_statusbar.h"
#include "ex_vfs.h"
#include "gui_icons.h"
#include "LanguageTest.h"

#define AUTO_OFF_TIME_CNT 4
#define SWITCH_OPEN        (1)
#define SWITCH_CLOSE    (0)

#define UPDATE_FILE_VOLUME  	VFS_UPDATE_VOLUME
#define UPDATE_FILE_PATH  		"1:upgrade.bin"

#define SETTING_BUFFER_SIZE 4

static int mViewOffet = 0;
static int mUsbSwitch = SWITCH_CLOSE;
static int mBtSwitch = SWITCH_CLOSE;
static char mAutoOffStr[32] = {0};
static char mScreeSaverTimeStr[32] = {0};
static char mBluetoothStr[32] = {0};

static int gBrightnessLevel[BRIGHTNESS_LEVEL_MAX] = {
        BRIGHTNESS_LEVEL_1_VALUE,
        BRIGHTNESS_LEVEL_2_VALUE,
        BRIGHTNESS_LEVEL_3_VALUE,
};//0 is max

static int gAutoOffTime[AUTO_OFF_TIME_CNT] = {30, 45, 60, 120};
static int gScreenTimes[SCREEN_SAVER_TIMER_MAX] = {15, 30, 45, 60};
static const char *gScreenTimeStr[SCREEN_SAVER_TIMER_MAX] = {"15s", "30s", "45s", "60s"};
static const char *gBrightnessLevelStr[BRIGHTNESS_LEVEL_MAX] = {"1", "2", "3"};
static const char *gBtLevelStr[BT_LEVEL_MAX] = {"ON", "OFF"};

enum {
    PINCODE_SETUP_STEP_VERIFY = 0,
    PINCODE_SETUP_STEP_ENTER_NEW,
    PINCODE_SETUP_STEP_CONFIRM,
    PINCODE_SETUP_STEP_STORE
};

static int getListSetValue(int id, char *value, int size) {
	int v;
	switch (id) {
		case SETTING_ITEM_SCREEN_OFF:
			v = gSettings->mScreenSaver;
			if (v == 0) {
				strcpy(value, "Off");
			} else {
				snprintf(value, size, "%ds", v);
			}
			return 1;
			break;
		case SETTING_ITEM_AUTO_SHUTDOWN:
			v = gSettings->mAutoShutdownTime;
			if (v == 0) {
				strcpy(value, "OFF");
			} else {
				snprintf(value, size, "%ds", v);
			}
			return 1;
			break;
		case SETTING_ITEM_BRIGHTNESS_LEVEL:
			v = gSettings->mBrightness;
			if (v == 0) {
				strcpy(value, "OFF");
			} else {
				snprintf(value, size, "%d", v);
			}
			return 1;
			break;
			/*case SETTING_ITEM_RANDOM_PIN_KEYPAD:
				v = gSettings->mRandPinKeypad;
				if ((v == 0) || (v == 1)) {
					strcpy(value, gRandPinKeypadStr[v]);
				} else {
					return 0;
				}
				return 1;
				break;*/
		case SETTING_ITEM_BLUETOOTH:
			v = mBtSwitch;
			if (v == 0) {
				strcpy(value, "OFF");
			} else {
				strcpy(value, "ON");
			}
			return 1;
			break;

		default:
			return 0;
	}
}

static int changeBluetooth(void) {
    int ret = 0;

    ret = gui_show_menu(res_getLabel(LANG_LABEL_BLUETOOTH), BT_LEVEL_MAX, !mBtSwitch, gBtLevelStr, TEXT_ALIGN_CENTER,
                       res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
    if (ret < 0) {
        return ret;
    } else if (ret == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    } else if (ret == BT_LEVEL_1) {
        ddi_bt_open();
        mBtSwitch = SWITCH_OPEN;
    } else if (ret == BT_LEVEL_2) {
        ddi_bt_close();
        mBtSwitch = SWITCH_CLOSE;
    }

    getListSetValue(SETTING_ITEM_BLUETOOTH, mBluetoothStr, sizeof(mBluetoothStr));

    return mBtSwitch;
}

int usbSwitch(int old_data) {
    if (old_data) {
        ddi_usb_close();
    } else {
        ddi_usb_open();
    }

    return (mUsbSwitch = old_data ? SWITCH_CLOSE : SWITCH_OPEN);
}

static int resetDevice(int param) {
    int ret = 0;

    do {
        ret = gui_disp_info(res_getLabel(LANG_LABEL_MENU_RESET), res_getLabel(LANG_LABEL_RESET_BACKUP_TIPS),
                            TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                           EVENT_KEY_F1);
        if (ret == EVENT_CANCEL) {
            return ret;
        } else if (ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else if (ret < 0) {
            db_msg("disclaimer alert false:%d", ret);
            return -1;
        }

        ret = gui_disp_info(res_getLabel(LANG_LABEL_MENU_RESET), res_getLabel(LANG_LABEL_MENU_RESET_TIPS),
                            TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                           EVENT_KEY_F1);
        if (ret == EVENT_CANCEL) {
            continue;
        } else if (ret == EVENT_OK) {

        } else if (ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else {
            db_msg("disclaimer alert false:%d", ret);
            return -2;
        }

        gui_show_state(res_getLabel(LANG_LABEL_MENU_RESET), res_getLabel(LANG_LABEL_RESET_PROCESS_TIPS));
        gui_on_process(10);
        ret = wallet_destorySeed(1, 30);
        db_msg("destorySeed ret:%d", ret);
        gui_on_process(60);
        doFactoryReset();
        gui_on_process(80);
        sec_reset_randkey(0);
        gui_on_process(100);
        break;
    } while (1);

    if (gSettings->mLang != 0) {
        settings_save(SETTING_KEY_LANGUAGE, settings_get_lang());
    }
    ddi_bt_close();
    gui_disp_info(res_getLabel(LANG_LABEL_MENU_RESET), res_getLabel(LANG_LABEL_RESET_SUCCESS_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                 NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
    ddi_sys_reboot();

    return 0;
}

static int changeAutoShutdownTime(void) {
    int count = AUTO_OFF_TIME_CNT;
    if (app_run_in_dev_mode()) {
        gAutoOffTime[AUTO_OFF_TIME_CNT - 1] = 0;
    }

    const char *items[AUTO_OFF_TIME_CNT * 10] = {0};
    int initIndex = 0;
    int ret = 0;
    char str[32] = {0};

    char datas[AUTO_OFF_TIME_CNT * 10] = {0};

    for (int j = 0; j < count; ++j) {
        if (gAutoOffTime[j] == 0) {
            snprintf(str, sizeof(str), "OFF");
        } else {
            snprintf(str, sizeof(str), "%ds", gAutoOffTime[j]);
        }
        memcpy(datas + 10 * j, str, strlen(str));
        items[j] = datas + 10 * j;
    }
    for (int i = 0; i < count; ++i) {
        if (gAutoOffTime[i] == gSettings->mAutoShutdownTime) {
            initIndex = i;
        }
    }
    ret = gui_show_menu(res_getLabel(LANG_LABEL_SET_ITEM_AUTO_SHUTDOWN), count, initIndex, items, TEXT_ALIGN_CENTER,
                       NULL, NULL, EVENT_KEY_F1);
    if (ret < 0) {
        return ret;
    } else if (ret == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    }
    if (ret >= 0 && ret < count) {
        settings_save(SETTING_KEY_AUTO_SHUTDOWN_TIME, gAutoOffTime[ret]);
        db_msg("auto shutdown time:%d ret:%d", gAutoOffTime[ret], ret);
    }
    getListSetValue(SETTING_ITEM_AUTO_SHUTDOWN, mAutoOffStr, sizeof(mAutoOffStr));
    ddi_sys_cmd(SYS_CMD_SET_INTO_DEEPSLEEP_TIME, gAutoOffTime[ret], 0);

    return 0;
}

static int changeScreenSaverTime(void) {
    int initIndex = 0;
    int ret = 0;
    char str[32] = {0};
    for (int i = SCREEN_SAVER_TIME_15S; i < SCREEN_SAVER_TIMER_MAX; ++i) {
        if (gScreenTimes[i] == (gSettings->mScreenSaver)) {
            initIndex = i;
            break;
        }
    }
    ret = gui_show_menu(res_getLabel(LANG_LABEL_SET_ITEM_SCREEN_OFF), SCREEN_SAVER_TIMER_MAX, initIndex, gScreenTimeStr,
                       TEXT_ALIGN_CENTER, NULL, NULL, EVENT_KEY_F1);
    if (ret < 0) {
        return ret;
    } else if (ret == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    }
    if (ret >= 0 && ret < SCREEN_SAVER_TIMER_MAX) {
        settings_save(SETTING_KEY_SCREEN_SAVER, gScreenTimes[ret]);
        db_msg("screen saver time:%d ret:%d", gScreenTimes[ret], ret);
    }
    getListSetValue(SETTING_ITEM_SCREEN_OFF, mScreeSaverTimeStr, sizeof(mScreeSaverTimeStr));
    ddi_sys_cmd(SYS_CMD_SET_AUTO_SLEEP_TIME, gScreenTimes[ret], 0);

    return 0;
}

static int changeBrightness(int old_data) {
    int initIndex = 0;
    int ret = 0;
    char str[32] = {0};

    for (int i = BRIGHTNESS_LEVEL_1; i < BRIGHTNESS_LEVEL_MAX; ++i) {
        if (gBrightnessLevel[i] == (gSettings->mBrightness)) {
            initIndex = i;
            break;
        }
    }

    ret = gui_show_menu(res_getLabel(LANG_LABEL_SET_BRIGHTNESS_LEVEL), BRIGHTNESS_LEVEL_MAX, initIndex,
                       gBrightnessLevelStr, TEXT_ALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                       res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
    if (ret < 0) {
        return ret;
    } else if (ret == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    }

    if (ret >= 0 && ret < BRIGHTNESS_LEVEL_MAX) {
        ddi_lcd_ioctl(DDI_LCD_CTL_BRIGHT, (uint32_t) gBrightnessLevel[ret], 0);
        db_msg("brightness level:%d ret:%d", gBrightnessLevel[ret], ret);
        settings_save(SETTING_KEY_BRIGHTNESS, gBrightnessLevel[ret]);
    }

    return 0;
}

static int changePassword(int param) {
    int ret = 0;
    unsigned char oldPasswd[PASSWD_HASHED_LEN] = {0};
    unsigned char newPasswd[PASSWD_HASHED_LEN] = {0};
    unsigned char confirmPasswd[PASSWD_HASHED_LEN] = {0};
    int step = PINCODE_SETUP_STEP_VERIFY;
    int err = 0;

    do {
        switch (step) {
            case PINCODE_SETUP_STEP_VERIFY: {
                ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_OLD_PASSWD), PIN_CODE_VERITY, oldPasswd, 1);
                //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
                if (!ret) {
                    step++;
                } else {
                    db_error("check old passwd error ret:%d", ret);
                    err = 1;
                }
            }
                break;
            case PINCODE_SETUP_STEP_ENTER_NEW: {
                ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_NEW_PASSWD), PIN_CODE_CHECK, newPasswd, 0);
                //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
                if (!ret) {
                    step++;
                } else {
                    db_error("enter passwd error ret:%d", ret);
                    err = 1;
                }
            }
                break;
            case PINCODE_SETUP_STEP_CONFIRM: {
                ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_CONFIRM_PASSWD), PIN_CODE_NONE, confirmPasswd, 0);
                //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
                if (!ret) {
                    if (memcmp(newPasswd, confirmPasswd, PASSWD_HASHED_LEN) == 0) {
                        step++;
                    } else {
                        ret = gui_disp_info(res_getLabel(LANG_LABEL_SET_ITEM_CHANGE_PASSWD),
                                            res_getLabel(LANG_LABEL_CHANGE_PIN_FAIL_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL,
                                           res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                        if (ret == EVENT_KEY_F1) {
                            return RETURN_DISP_MAINPANEL;
                        }
                        step = PINCODE_SETUP_STEP_ENTER_NEW;
                    }
                } else {
                    err = 1;
                }
            }
                break;
            case PINCODE_SETUP_STEP_STORE: {
                ret = sapi_change_passwd((const unsigned char *) oldPasswd, PASSWD_HASHED_LEN,
                                         (const unsigned char *) newPasswd, PASSWD_HASHED_LEN);
                db_msg("sapi_change_passwd ret:%d", ret);
                memzero(oldPasswd, PASSWD_HASHED_LEN);
                memzero(newPasswd, PASSWD_HASHED_LEN);
                memzero(confirmPasswd, PASSWD_HASHED_LEN);
                if (!ret) {
                    ret = gui_disp_info(res_getLabel(LANG_LABEL_SET_ITEM_CHANGE_PASSWD),
                                       res_getLabel(LANG_LABEL_CHANGE_PIN_SUCCESS_TIPS),
                                       TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL,
                                       res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
                    if (ret == EVENT_KEY_F1) {
                        return RETURN_DISP_MAINPANEL;
                    }
                    return 0;
                } else {
                    err = 1;
                    ret = dialog_error3(0, ret, "System error.");
                    if (ret == EVENT_KEY_F1) {
                        return RETURN_DISP_MAINPANEL;
                    }
                }
                ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
            }
                break;
            default:
                break;
        }

        ddi_sys_msleep(50);
    } while (!err);
    memzero(oldPasswd, PASSWD_HASHED_LEN);
    memzero(newPasswd, PASSWD_HASHED_LEN);
    memzero(confirmPasswd, PASSWD_HASHED_LEN);

    if (ret == RETURN_DISP_MAINPANEL) {
        return RETURN_DISP_MAINPANEL;
    }

    return err ? -1 : 0;
}

int showAboutWallet(void) {
    char str[128], blename[32], sn[24];
    char device_name[32];
    int ret = 0, os_verison;
    int width = 0;

    memset(str, 0x0, sizeof(str));
    memset(blename, 0x0, sizeof(blename));
    memset(device_name, 0x0, sizeof(device_name));
    memset(sn, 0x0, sizeof(sn));

    dwin_init();
    //name
    get_device_name(device_name, sizeof(device_name), 1);
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s: %s", res_getLabel(LANG_LABEL_WALLET_NAME), device_name);
    width = ddi_lcd_get_text_width(str);
    if (width > g_gui_info.uiScrWidth) {
        snprintf(str, sizeof(str), "%s:\n%s", res_getLabel(LANG_LABEL_WALLET_NAME), device_name);
    }
    SetWindowMText(0, str);

    //type
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s: %s %s", res_getLabel(LANG_LABEL_PRODUCT_TYPE), PRODUCT_BRAND_VALUE,
             PRODUCT_NAME_VALUE);
    width = ddi_lcd_get_text_width(str);
    if (width > g_gui_info.uiScrWidth) {
        snprintf(str, sizeof(str), "%s:\n%s %s", res_getLabel(LANG_LABEL_PRODUCT_TYPE), PRODUCT_BRAND_VALUE,
                 PRODUCT_NAME_VALUE);
    }
    SetWindowMText(0, str);

    //version
    os_verison = ddi_sys_get_firmware_ver(OS_VER);
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s: %s-%d", res_getLabel(LANG_LABEL_FIRMWARE_VERSION), DEVICE_APP_VERSION, os_verison);
    width = ddi_lcd_get_text_width(str);
    if (width > g_gui_info.uiScrWidth) {
        snprintf(str, sizeof(str), "%s:\n%s-%d", res_getLabel(LANG_LABEL_FIRMWARE_VERSION), DEVICE_APP_VERSION,
                 os_verison);
    }
    SetWindowMText(0, str);

    //sn
    device_get_sn(sn, 24);
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s: %s", res_getLabel(LANG_LABEL_DEVICE_SN), sn);
    width = ddi_lcd_get_text_width(str);
    if (width > g_gui_info.uiScrWidth) {
        snprintf(str, sizeof(str), "%s:\n%s", res_getLabel(LANG_LABEL_DEVICE_SN), sn);
    }
    SetWindowMText(0, str);

    //blename
    st_bt_info bt_flash_info;
    memset(&bt_flash_info, 0x0, sizeof(st_bt_info));
    ddi_flash_read(YC_INFOR_ADDR, (uint8_t *) &bt_flash_info, sizeof(bt_flash_info));
    if ((bt_flash_info.flag == BT_INFOR_FLAG) && (!is_empty_string(bt_flash_info.ble_name))) {
        memcpy(blename, bt_flash_info.ble_name, sizeof(bt_flash_info.ble_name));
    }
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s: %s", res_getLabel(LANG_LABEL_DEVICE), blename);
    SetWindowMText(0, str);

    //active time
    const char *actime_title = res_getLabel(LANG_LABEL_DEVICE_ACTIVE_TIME);
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s:", actime_title);
    SetWindowMText(0, str);
    memset(str, 0x0, sizeof(str));
    int atime = device_get_active_time();
    if (atime > 100) {
        format_time(str, sizeof(str), atime, 0, 2);
    }
    SetWindowMText(0, str);

    ret = ShowWindowTxt(res_getLabel(LANG_LABEL_SET_ITEM_ABOUT), TEXT_ALIGN_LEFT,
                        res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK));
    dwin_destory();

    return ret;
}

static int other_info(void) {
    int ret = -1;
    uint32_t filelen = 0;
    FILE_INFO_ST file_info;
    uint8_t tmpbuf[128] = {0};
    DynamicViewCtx *view;

    memset((uint8_t * ) & file_info, 0x0, sizeof(FILE_INFO_ST));
    ddi_flash_read(INTERNAL_APP_ADDR, (uint8_t * ) & file_info, sizeof(FILE_INFO_ST));

    if (memcmp(file_info.identifier, "FILE_INFO", 9) != 0) {
        ALOGE("file_info.identifier:%x,%x", file_info.identifier[0], file_info.identifier[1]);
        return -1;
    }

    if (file_info.Image_ver < 10000) {
        ALOGE("invalid Image_ver:%d", file_info.Image_ver);
        return -3;
    }

    dwin_init();
    snprintf(tmpbuf, sizeof(tmpbuf), "Date: %s\nTime: %s\nVoltage: %d\nBat Status: %d", file_info.Date, file_info.Time,
             ddi_sys_bat_vol(), ddi_sys_bat_status());
    view_add_txt(1, tmpbuf);

    uint32_t os_verison, font_verison, label_verison, boot_verison, update_verison;
    os_verison = ddi_sys_get_firmware_ver(OS_VER);
    font_verison = ddi_sys_get_firmware_ver(FONT_VER);
    label_verison = res_get_label_version();
    boot_verison = ddi_sys_get_firmware_ver(BOOT_VER);
    update_verison = ddi_sys_get_firmware_ver(RECOVERY_VER);
    db_msg("os_verison:%d", os_verison);
    db_msg("font_verison:%d", font_verison);
    db_msg("label_verison:%d", label_verison);
    db_msg("boot_verison:%d", boot_verison);
    db_msg("update_verison:%d", update_verison);

    snprintf(tmpbuf, sizeof(tmpbuf), "app_ver:%d", DEVICE_APP_INT_VERSION);
    view_add_txt(0, tmpbuf);

    snprintf(tmpbuf, sizeof(tmpbuf), "os_ver:%d", os_verison);
    view_add_txt(0, tmpbuf);

    snprintf(tmpbuf, sizeof(tmpbuf), "font_ver:%d", font_verison);
    view_add_txt(0, tmpbuf);

    snprintf(tmpbuf, sizeof(tmpbuf), "label_ver:%d", label_verison);
    view_add_txt(0, tmpbuf);

    snprintf(tmpbuf, sizeof(tmpbuf), "boot_ver:%d", boot_verison);
    view_add_txt(0, tmpbuf);
	
    snprintf(tmpbuf, sizeof(tmpbuf), "update_ver:%d", update_verison);
    view_add_txt(0, tmpbuf);

    snprintf(tmpbuf, sizeof(tmpbuf), "ble state:%d", ddi_bt_get_status());
    view_add_txt(0, tmpbuf);

    ret = ShowWindowTxt(NULL, TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK),
                        res_getLabel(LANG_LABEL_SUBMENU_OK));
    dwin_destory();

    return ret;
}

static int updateFirmware(void) {
    int ret = 0;
    const char *tips = NULL;

    int vol = ddi_sys_bat_vol();
    if (vol < BATTERY_UPDATE_MIN_VOL) {
        db_error("vol:%d", vol);
        gui_disp_info(res_getLabel(LANG_LABEL_ALERT), res_getLabel(LANG_LABEL_UPGRADE_BATTERY_TIPS), TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK),
                      res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
        ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        return -1;
    }

    ret = gui_disp_info(res_getLabel(LANG_LABEL_UPGRADE), res_getLabel(LANG_LABEL_OTA_BACKUP_PHRASES_TIPS), TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK),
                        res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
    if (ret != EVENT_OK) {
        ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        return -1;
    }

    ret = gui_disp_info(res_getLabel(LANG_LABEL_UPGRADE), res_getLabel(LANG_LABEL_DOWNLOAD_FW_TIPS), TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK),
                        res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
    if (ret != EVENT_OK) {
        ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        return -2;
    }

    //erase fs inode
    ddi_flash_sector_erase(INTERNAL_TEMP_ADDR);

    ddi_usb_open();
    ddi_vfs_mount(UPDATE_FILE_VOLUME);
    ret = ddi_vfs_mkfs(UPDATE_FILE_VOLUME);
    if (ret < 0) {
        db_error("mkfs error ret:%d", ret);
        ddi_vfs_unmount(UPDATE_FILE_VOLUME);
        ddi_usb_close();
        ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        return -3;
    }
    set_temp_screen_time(-1);
    int passwd_error = 0, t = 0;
    do {
        ret = gui_disp_info(res_getLabel(LANG_LABEL_UPGRADE), res_getLabel(LANG_LABEL_CONNECT_PC_TIPS), TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK),
                            res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
        if (ret != EVENT_OK) {
            db_error("connect pc tips false ret:%d", ret);
            break;
        }

        loading_win_start(0, res_getLabel(LANG_LABEL_UPGRADE), res_getLabel(LANG_LABEL_CHECKING), 0);
        ddi_vfs_unmount(UPDATE_FILE_VOLUME);
        ddi_vfs_mount(UPDATE_FILE_VOLUME);
        for (t = 0; t < 3; t++) {
            ret = ddi_ota_prepare();
            if (ret == UPGRADE_FW_VERIFY_DIGEST_FAILED) {
                ddi_sys_msleep(100);
            } else {
                break;
            }
        }
        if (ret != 0) {
            db_error("prepare upgrade false ret:%d", ret);
            if (ret == UPGRADE_FW_NOT_FOUND) {
                tips = res_getLabel(LANG_LABEL_NOT_FOUND_FW_TIPS);
            } else {
                tips = "Invalid firmware.";
            }
            gui_disp_info(res_getLabel(LANG_LABEL_UPGRADE), tips, TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                          res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
        } else {
            db_msg("prepare upgrade OK,t:%d", t);
            gui_disp_info(res_getLabel(LANG_LABEL_UPGRADE), res_getLabel(LANG_LABEL_FOUND_FW_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
            if (gHaveSeed) {
                if (checkPasswdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_PASSWD),
                                        PASSKB_FLAG_RANDOM | PASSKB_FLAG_NOT_SWITCH_GUIDE) != 0) {
                    if (!gHaveSeed) {
                        passwd_error = 1;
                    }
                    continue;
                }
            }
            loading_win_start(0, res_getLabel(LANG_LABEL_UPGRADE), res_getLabel(LANG_LABEL_UPGRADING), 0);
            settings_save(SETTING_KEY_OTA_PRE_VERSION, DEVICE_APP_INT_VERSION);
            ddi_usb_close();
            ret = ddi_ota_upgrade();
            if (ret == 0) {
                ddi_bt_disconnect();
                ddi_bt_close();
                ddi_sys_msleep(100);
                ddi_sys_reboot();
            } else {
                settings_save(SETTING_KEY_OTA_PRE_VERSION, 0);
                char buff[48] = {0};
                snprintf(buff, sizeof(buff), "Upgrade failed(%d).", ret);
                gui_disp_info(res_getLabel(LANG_LABEL_UPGRADE), buff, TEXT_ALIGN_CENTER | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                              res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
                break;
            }
        }
        ddi_sys_msleep(50);
    } while (1);

    ddi_vfs_remove(UPDATE_FILE_PATH);
    ddi_vfs_unmount(UPDATE_FILE_VOLUME);
    ddi_usb_close();
    set_temp_screen_time(0);

    ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
    return ret;
}

int showDownloadApp() {
    gui_creat_win(res_getLabel(LANG_LABEL_DOWNLOAD_APP_TITLE), NULL, NULL);

    strRect rect;
    rect.m_x0 = (g_gui_info.uiScrWidth - 50) / 2;
    rect.m_x1 = rect.m_x0 + 50;
    rect.m_y0 = 12;
    rect.m_y1 = rect.m_y0 + 50;
    gui_sdk_show_image(&rect, gImage_download_50);
    ddi_lcd_brush_screen();

    int key = 0;
    int brush_title = 1;
    while (1) {
        ddi_key_read(&key);
        if (key > 0) {
            break;
        }
        if ((brush_title == 1) || (brush_title > 20)) {
            gui_cb_check_status_bar();
            brush_title = 1;
        }
        brush_title++;

        ddi_sys_msleep(50);
    }
}

static void SettingInit(void) {
    mUsbSwitch = SWITCH_CLOSE;

    int RetIcon = -1;
    RetIcon = gui_check_bt_status();
    if (RetIcon == SB_ICON_BT_OPEN || RetIcon == SB_ICON_BT_CONNECT) {
        mBtSwitch = SWITCH_OPEN;
    } else {
        mBtSwitch = SWITCH_CLOSE;
    }
    // db_msg("mBtSwitch:%d", mBtSwitch);

    memset(mAutoOffStr, 0x0, sizeof(mAutoOffStr));
    getListSetValue(SETTING_ITEM_AUTO_SHUTDOWN, mAutoOffStr, sizeof(mAutoOffStr));

    memset(mScreeSaverTimeStr, 0x0, sizeof(mScreeSaverTimeStr));
    getListSetValue(SETTING_ITEM_SCREEN_OFF, mScreeSaverTimeStr, sizeof(mScreeSaverTimeStr));

    memset(mBluetoothStr, 0x0, sizeof(mBluetoothStr));
    getListSetValue(SETTING_ITEM_BLUETOOTH, mBluetoothStr, sizeof(mBluetoothStr));
}

int SettingWin(void) {

    SettingInit();

    MENU_SET_CFG SETTING_LABEL_CFG[] = {
            {LANG_LABEL_ITEM_PASSPHRASE,        VAL_OFF, SUB_ON, NULL,               PassphraseGuide,        0},
            {LANG_LABEL_ITEM_VERIFY,            VAL_OFF, SUB_ON, NULL,               VerifyWinGuide,         0},
            {LANG_LABEL_SET_ITEM_SCREEN_OFF,    VAL_OFF, SUB_ON, mScreeSaverTimeStr, changeScreenSaverTime,  0},
            {LANG_LABEL_SET_ITEM_AUTO_SHUTDOWN, VAL_OFF, SUB_ON, mAutoOffStr,        changeAutoShutdownTime, 0},
            {LANG_LABEL_SET_ITEM_CHANGE_PASSWD, VAL_OFF, SUB_ON, NULL,               changePassword,         0},
            {LANG_LABEL_SET_ITEM_CHANGE_LANG,   VAL_OFF, SUB_ON, NULL,               setupLang,              settings_get_lang()},
            {LANG_LABEL_SET_BRIGHTNESS_LEVEL,   VAL_OFF, SUB_ON, NULL,               changeBrightness,       0},
            {LANG_LABEL_BLUETOOTH,              VAL_OFF, SUB_ON, mBluetoothStr,      changeBluetooth,        0},
            {LANG_LABEL_UPGRADE,                VAL_OFF, SUB_ON, NULL,               updateFirmware,         0},
            {LANG_LABEL_MENU_RESET,             VAL_OFF, SUB_ON, NULL,               resetDevice,            0},
            {LANG_LABEL_DOWNLOAD_APP_TITLE,     VAL_OFF, SUB_ON, NULL,               showDownloadApp,        0},
            {LANG_LABEL_SET_ITEM_ABOUT,         VAL_OFF, SUB_ON, NULL,               showAboutWallet,        0},
#ifdef BUILD_FOR_DEV
            {LANG_LABEL_NONE,                   VAL_OFF, SUB_ON, "language test",    LanguageTest,           0},
#endif
    };

    int mItemTotal = sizeof(SETTING_LABEL_CFG) / sizeof(MENU_SET_CFG);
    int max_0ffset = ((mItemTotal / SETTING_BUFFER_SIZE) * SETTING_BUFFER_SIZE);
    max_0ffset = mItemTotal % SETTING_BUFFER_SIZE == 0 ? max_0ffset - SETTING_BUFFER_SIZE : max_0ffset;
    mViewOffet = 0;

    int ret = 0, curInx = 0;
    while (1) {
        int page_size = mViewOffet + SETTING_BUFFER_SIZE > mItemTotal ? mItemTotal % SETTING_BUFFER_SIZE : SETTING_BUFFER_SIZE;
        const char *pTitle = res_getLabel(LANG_LABEL_SET_TITLE);
        db_msg("page_size:%d mViewOffet:%d curInx:%d", page_size, mViewOffet, curInx);
        ret = gui_show_rich_menu_setting(pTitle, MENU_LIST | MENU_ICON_NUM | MENU_ONCE,
                                 page_size, curInx,
                                 SETTING_LABEL_CFG + mViewOffet);

        db_msg("gui_show_rich_menu_setting ret:%x", ret);
        if (ret == EVENT_NEXT_MENU) {
            if (mViewOffet < max_0ffset) {
                mViewOffet = mViewOffet + SETTING_BUFFER_SIZE;
            } else {
                mViewOffet = 0;
            }
            curInx = 0;
        } else if (ret == EVENT_LAST_MENU) {
            if (mViewOffet >= SETTING_BUFFER_SIZE) {
                mViewOffet = mViewOffet - SETTING_BUFFER_SIZE;
                curInx = SETTING_BUFFER_SIZE - 1;
            } else {
                mViewOffet = max_0ffset;
                curInx = mItemTotal % SETTING_BUFFER_SIZE > 0 ? mItemTotal % SETTING_BUFFER_SIZE - 1 : SETTING_BUFFER_SIZE - 1;
            }
        } else if (ret == RETURN_DISP_MAINPANEL || ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else if (ret >= 0 && ret < SETTING_BUFFER_SIZE) {
            curInx = ret;
            db_msg("gui_show_rich_menu_setting curInx:%d", curInx);
            continue;
        } else {
            break;
        }

        ddi_sys_msleep(50);
    }

    return ret;
}
