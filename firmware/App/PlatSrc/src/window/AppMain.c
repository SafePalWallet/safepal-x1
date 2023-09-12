#define LOG_TAG "main"

#include "plat_api.h"
#include "ex_types.h"
#include "libddi.h"
#include "BtProcWin.h"
#include "debug.h"
#include "xstr.h"
#include "global.h"
#include "settings.h"
#include "secure_api.h"
#include "storage_manager.h"
#include "gui_sdk.h"
#include "cdrLang.h"
#include "device.h"
#include "wallet_proto.h"
#include "wallet_manager.h"
#include "common_util.h"
#include "FactoryWin.h"
#include "GuideWin.h"
#include "BtProcWin.h"
#include "wallet_api.h"
#include "resource.h"
#include "rtc.h"
#include "gui_statusbar.h"
#include "base58.h"
#include "SettingWin.h"
#include "update.h"
#include "gui_event.h"
#include "gui_api.h"
#include "wallet_util_hw.h"

extern uint32_t Load$$ER_IROM1$$Base;
extern uint32_t Load$$ER_IROM1$$Length;
extern uint32_t Image$$ER_IROM1$$Length;
extern uint32_t Image$$ER_IROM1$$Limit;

extern uint32_t Image$$RW_IRAM1$$Base;
extern uint32_t Image$$RW_IRAM1$$Limit;
extern uint32_t Image$$RW_IRAM1$$Length;

extern uint32_t Load$$RW_IRAM1$$Base;

extern uint32_t Image$$RW_IRAM1$$ZI$$Base;
extern uint32_t Image$$RW_IRAM1$$ZI$$Limit;
extern uint32_t Image$$RW_IRAM1$$ZI$$Length;

static long mShutdownFutureTime = 0;
static long mShutdownCountdownTime = 0;

const FILE_INFO_ST file_info[] __attribute__((section(".ARM.__at_0x010A5000"))) = {
        "FILE_INFO", \
    (uint32_t) 0x04, \
    (uint32_t) 0x01, \
    (uint32_t) 0x01, \
    (uint32_t) DEVICE_APP_INT_VERSION, \
    (uint32_t) (&Load$$ER_IROM1$$Base), \
    (uint32_t) (&Load$$ER_IROM1$$Length), \
    (uint32_t) (&Image$$RW_IRAM1$$Length), \
    0xffffffff, \
    "X1_SafePal", \
    (__DATE__), \
    (__TIME__), \
    (uint32_t) INTERNAL_APP_SIZE, \
    0 \
};

int main(void *data) __attribute__((section(".ARM.__at_0x010A5200")));

static void CopyCode2Ram() {
    uint32_t SrcBase;
    uint32_t DesBase;
    uint8_t *pSrc, *pDes;
    uint32_t count;

    DesBase = (uint32_t) (&Image$$RW_IRAM1$$Base);
    SrcBase = (uint32_t) (&Image$$ER_IROM1$$Limit);
    count = (uint32_t) (&Image$$RW_IRAM1$$Length);

    pSrc = (uint8_t *) SrcBase;
    pDes = (uint8_t *) DesBase;
    //uart_printf("pSrc = %x\n",pSrc);
    while (count--) {
        *pDes++ = *pSrc++;
    }

    DesBase = (uint32_t) (&Image$$RW_IRAM1$$Limit);
    count = (uint32_t) (&Image$$RW_IRAM1$$ZI$$Limit) - (uint32_t) (&Image$$RW_IRAM1$$Limit);

    pDes = (uint8_t *) DesBase;
    while (count--) {
        *pDes++ = 0x00;
    }
}

static void init_process(void *data) {
    init_ddi_item((const ddi_cmd_item *) data);

#ifdef DEBUG_ON
    uint8_t str[32] = {0};
    snprintf(str, sizeof(str), "%s %s %s\r\n", "welcome to app", "ver:", DEVICE_APP_VERSION);

#if DEBUG_UART
    ddi_uart_open(0,115200);
    ddi_uart_write(0, str, strlen(str));
#elif DEBUG_USB
    ddi_usb_open();
    ddi_usb_write(str, strlen(str));
#endif

#endif

    ddi_lcd_open();
    ddi_key_open();
    //ddi_sec_tamper_clr();
    //ddi_usb_open();
}

static int wallet_init_check(int init_ret) {
    sec_state_info info;
    if (init_ret == 0) {
        if (sapi_get_state_info(&info) != 0) {
            db_serr("get state info false");
            init_ret = -1;
        }
    }
    if (init_ret == 0) {
        if (gHaveSeed) {
            if (info.seed_state != 1) {
                db_error("seed diff sapi:%d local:%d", info.seed_state, gHaveSeed);
                settings_set_have_seed(0);
                return 1;
            } else if (info.account_id) {
                uint64_t id = device_read_seed_account();
                if (!id) {
                    db_serr("auto save se account_id:%llx", info.account_id);
                    device_save_seed_account(info.account_id);
                } else if (id != info.account_id) {
                    db_serr("invalid nvm account_id:%llx != se account_id:%llx", id, info.account_id);
                    settings_set_have_seed(0);
                    return 2;
                }
            }
        }
        return 0;
    } else {
        if (init_ret < 0 && gHaveSeed) {
            db_error("set have no seed");
            settings_set_have_seed(0);
        }
        if (init_ret == 1) {
            if (GLobal_IN_OTAOK_Win) {
                db_msg("not SE OTA,use OTAOK win");
            } else {
                if (gHaveSeed) {
                    db_error("set have no seed,wm init ret:%d", init_ret);
                    settings_set_have_seed(0);
                }
                return 3;
            }
        } else {
            return 4;
        }
        return 0;
    }
    return 0;
}

static int wallet_main2_init() {
    proto_init_env(0);
    //init secure api
    int device_inited = device_is_inited();
    int ret = wallet_init();
    if (ret < 0 && gHaveSeed) {
        db_error("wallet_init ret:%d but have seed,retry", ret);
        ddi_sys_msleep(300);
        ret = wallet_init();
    }
    db_msg("device_inited:%d wallet_init ret:%d,gHaveSeed:%d", device_inited, ret, gHaveSeed);
    if (device_inited) {
        ret = wallet_init_check(ret);
        if (ret != 0) {
            db_serr("wallet_init_check error ret:%d", ret);
            return ret;
        }
    } else {
        if (gHaveSeed) { //error??
            settings_set_have_seed(0);
        }
    }

    settings_backup_to_nvm(1);

    Global_App_Inited = 1;

    return 0;
}

int destoryDevice(void) {
    if (app_run_in_dev_mode()) {
        db_secure("dev mode,skip destory");
        return -1;
    }

    if (!device_is_inited()) {
        db_serr("device not inited,skip");
        return -1;
    }

    int ret = wallet_destorySeed(0, 0);
    db_secure("destorySeed ret:%d", ret);
    doFactoryReset();
    sec_reset_randkey(0);
    //ret = device_destory_self();
    //db_secure("destory self ret:%d", ret);
    //force shutdown
    mShutdownFutureTime = getClockTime();
    return 0;
}

int dispOTAOK(void) {
    char tips[256] = {0};
    settings_save(SETTING_KEY_OTA_PRE_VERSION, 0);
    const char *format = (res_getLabel(LANG_LABEL_UPGRADE_SUCCESS));
    snprintf(tips, sizeof(tips), format, DEVICE_APP_VERSION);
    gui_disp_info(res_getLabel(LANG_LABEL_UPGRADE), tips, TEXT_ALIGN_CENTER | TEXT_VALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
}

static int hw_break_cnt = 0;

static void Callback_GetTamperStaus(unsigned char *str, unsigned short len) {
#ifdef CONFIG_DETECT_HW_BREAK
    if (device_get_hw_break_state(1) == 1) {
        hw_break_cnt++;
        db_msg("broken hw_break_cnt:%d", hw_break_cnt);
    } else {
        //db_msg("cover is ok");
        hw_break_cnt = 0;
    }
    if (gHaveSeed && hw_break_cnt > 10) {
        db_serr("hw_break_cnt:%d,destory seed", hw_break_cnt);
        destoryDevice();
        hw_break_cnt = 0;
    }
#endif
}

int main(void *data) {
    CopyCode2Ram();
    init_process(data);

    gui_sdk_init();

    if (settings_init() != 0) {
        db_error("settings_init false");
        return 0;
    }
    //wallet_main2_thread
    int ret2 = wallet_main2_init();
    db_msg("wallet_main2_init ret2:%d", ret2);

    res_initLangAndFont();

    if (!device_is_inited()) {
        db_msg("device not inited");
        FactoryWin();
    } else if (gHaveSeed != 1) {
        startGuide();
    } else if (gSettings->mOtaPreVersion > 0 && (gSettings->mOtaPreVersion <= DEVICE_APP_INT_VERSION)) {
        ddi_bt_open();
        dispOTAOK();
    }

    ddi_soft_timer_start(TMR_SHUTDOWN_LOOP, MODE_PERIODIC, 1000, (callback *) Callback_GetTamperStaus, NULL, 0);

    while (1) {
        mainPanel();
        ddi_sys_msleep(30);
    }

    return 0;
}
