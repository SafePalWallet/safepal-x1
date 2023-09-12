#ifndef BT_PROC_WIN_H_
#define BT_PROC_WIN_H_

#include "ex_types.h"
#include "wallet_proto.h"
#include "qr_pack.h"

#define BT_UNKNOWN_ERROR -199

#define DEVICE_NOTIFY_COMMON_TYPE  (0)
#define DEVICE_NOTIFY_PACKET_TYPE  (1)

#define DEVICE_USER_CANCEL            (1)
#define DEVICE_NOT_SUPPORT            (2)
#define DEVICE_READY                (3)
#define DEVICE_INJECTION_SN_SUCCESS    (80001)
#define DEVICE_INJECTION_SN_FAIL    (80002)

enum bt_status {
    STAT_BT_INIT = 0,
    STAT_BT_START_PAIRING,
    STAT_BT_ENCRY_STATE,
    STAT_BT_DISP_CONFIRM_KEY,
    STAT_BT_CONFIRM_KEY,
    STAT_BT_GET_CONFIRM_KEY_STAT,
    STAT_BT_GET_ENCRY_STATE,
    STAT_DATA_RECV,
    STAT_DATA_HANDLE,
    STAT_TRANS_PROC,
    STAT_TRANS_SIGN,
    STAT_DATA_SEND,
    STAT_ERR_RSP,
};

typedef struct {
    int code;
    char *title;
    char *msg;
} tips_st;

#define PROC_BLE_GET_ENC_STATE_CNT        (20)
#define PROC_BLE_GET_PAIR_CODE_CNT        (20)
#define PROC_BLE_CONFIRM_PAIR_STATE_CNT    (300)
#define PROC_BLE_NOTIFY_CNT                (3)

#define PROC_WITHOUT_RSP                (300)
#define PROC_OTA_INFO_RSP                (301)

//error
#define PROC_ERROR_COIN_ALL_NOT_SUPPORT (-1100)
#define PROC_ERROR_BLE_SEND_DATA        (-1101)
#define PROC_ERROR_SIGN_FAILED          (-1102)

#define respCommonNotify(c) procResponeNotify(DEVICE_NOTIFY_COMMON_TYPE, (c), NULL)

int mainPanel(void);

int procFactoryInit(void);

int btProcDeInit(void);

int btProcInit(ProtoClientMessage *msg);

int BtProcWin(void);

int procResponeNotify(int type, int code, qr_packet_header_info *h);

int procActiveDevice(void);

int dispPairCode(void);

#endif /**/
