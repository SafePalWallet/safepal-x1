#include <string.h>
#include "global.h"
#include "platform.h"
#include "ex_sys.h"
#include "GuideWin.h"
#include "libddi.h"

#ifdef BUILD_FOR_DEV
static int app_run_mode = 0;
#endif

int Global_FactoryTesting = 0;
int Global_USB_Change = 0;
int Global_USB_State = 0;//screenOn when usbState change
int Global_App_Inited = 0;
int Global_Have_New_DBCoin = 0;
int Global_Guide_abort = 0;
int Global_Temp_Screen_Time = 0;
int Global_Factory_Pass = 0;
#ifdef BUILD_FOR_DEV
int GLobal_PIN_Passed = 1;
#else
int GLobal_PIN_Passed = 0;
#endif
int GLobal_IN_OTAOK_Win = 0;
unsigned long long Global_Key_Random_Source = 5381;
int gProcessing = 0;
int Global_Skip_Boot_Private = 0;
int Global_Device_Account_Index = 0;
uint64_t gSeedAccountId = 0;
int gHaveSeed = 0;
int GLobal_CoinsWin_EditMode = 0;
int Global_Is_Show_Mnemonic = 0;
int Global_Is_Key_Down_End = 0;
int Global_Is_BLE_Recv_Data = 0;
int Global_Ble_Mtu = 0;
int Global_Ble_Process_Step = 0;
int GLobal_Is_Coin_EVM_Category = 0;

#ifdef BUILD_FOR_DEV

void set_app_run_mode(int m) {
    app_run_mode = m;
}

#endif

int app_run_in_dev_mode() {
#ifdef BUILD_FOR_DEV
    return app_run_mode;
#else
    return 0;
#endif
}

int set_temp_screen_time(int t) {
    int i = Global_Temp_Screen_Time;
    if (t == -1) {
        ddi_sys_cmd(SYS_CMD_SET_AUTO_SLEEP_AVAIBLE, 0, NULL);
    } else if (t == 0) {
        ddi_sys_cmd(SYS_CMD_SET_AUTO_SLEEP_TIME, DEFAULT_SCREEN_SAVER_TIME, 0);
        ddi_sys_cmd(SYS_CMD_SET_AUTO_SLEEP_AVAIBLE, 1, NULL);
    } else {
        Global_Temp_Screen_Time = t;
        ddi_sys_cmd(SYS_CMD_SET_AUTO_SLEEP_TIME, Global_Temp_Screen_Time, 0);
    }

    return i;
}

