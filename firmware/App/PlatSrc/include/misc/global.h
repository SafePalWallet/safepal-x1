
#ifndef WALLET_GLOBAL_H
#define WALLET_GLOBAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
extern int Global_FactoryTesting;
extern int Global_USB_Change;
extern int Global_USB_State;
extern int Global_App_Inited;
extern int Global_Have_New_DBCoin;
extern int Global_Guide_abort;
extern int Global_Temp_Screen_Time;
extern int Global_Factory_Pass;
extern int GLobal_PIN_Passed;
extern int GLobal_IN_OTAOK_Win;
extern int gProcessing;
extern int Global_Skip_Boot_Private;
extern unsigned long long Global_Key_Random_Source;
extern int Global_Device_Account_Index;
extern uint64_t gSeedAccountId;
extern int gHaveSeed;
extern int GLobal_CoinsWin_EditMode;
extern int Global_Is_Show_Mnemonic;
extern int Global_Is_Key_Down_End;
extern int Global_Is_BLE_Recv_Data;
extern int Global_Ble_Mtu;
extern int Global_Ble_Process_Step;
extern int GLobal_Is_Coin_EVM_Category;

#ifdef BUILD_FOR_DEV

void set_app_run_mode(int m);

#endif

int app_run_in_dev_mode(void);

//const char *get_system_res_point(void);

int set_temp_screen_time(int t);



#ifdef __cplusplus
}
#endif

#endif
