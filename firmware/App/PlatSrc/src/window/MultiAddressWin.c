#include "ex_types.h"
#include "debug.h"
#include "gui_sdk.h"
#include "MultiAddressWin.h"
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
#include "common_util.h"

#define MULTI_PAGE_SIZE      3
#define ABB_NAME_SIZE        18

typedef struct {
    char address[MAX_ADDR_SIZE];
    char abb_address[ABB_NAME_SIZE];
    int index;
} AddressInfo;

static HDNode mHDNode;
static AddressInfo mItems[MULTI_PAGE_SIZE];
static char *addr_uname = NULL;
static int mCoinType = 0;
static int mViewOffet = 0;
char *symbol = NULL;
int max_btc_address_size = 11;
int max_btc_address_0ffset = 3;

static int showAddress(int index) {
    db_msg("jumpToAddressWin index:%d", index);
    if (index >= MULTI_PAGE_SIZE) {
        db_error("index err");
        return -1;
    }

    if (mCoinType == 0 || addr_uname == NULL) {
        db_error("mCoinType or addr_uname err");
        return -2;
    }

    AddressInfo item = mItems[index];
    int ret = gui_disp_info(symbol ? symbol : "", item.address, TEXT_ALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                           res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
    if (ret == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    }

    return 0;
}

static MENU_SET_CFG mAddressMenu[MULTI_PAGE_SIZE] = {
        {ID_NONE, VAL_OFF, SUB_ON, NULL, showAddress, 0},
        {ID_NONE, VAL_OFF, SUB_ON, NULL, showAddress, 0},
        {ID_NONE, VAL_OFF, SUB_ON, NULL, showAddress, 0},
        // {ID_NONE, VAL_OFF, SUB_ON, NULL, showAddress, 0},
};

static int refreshAddressList() {
    db_msg("mViewOffet:%d", mViewOffet);
    char temp_address[ABB_NAME_SIZE];
    int offset = 0;
    int len = 0;
    for (int i = 0; i < MULTI_PAGE_SIZE; i++) {
        memset(&mItems[i].address, 0, MAX_ADDR_SIZE);
        memset(&mItems[i].abb_address, 0, ABB_NAME_SIZE);
        memset(temp_address, 0, ABB_NAME_SIZE);

        offset = i + mViewOffet;
        if (i + mViewOffet < max_btc_address_size) {
            len = wallet_genAddress(mItems[i].address, sizeof(mItems[i].address), &mHDNode, mCoinType, addr_uname,
                                    offset, 0);
            mItems[i].index = i;
            db_msg("mItems[%d].address:%s", i, mItems[i].address);
            if (len == 0) {
                db_error("get hdnode failed len:%d", len);
                return -11;
            }

            if (len > 10) {
                omit_string(temp_address, mItems[i].address, 3, 5);
            } else {
                memcpy(temp_address, &mItems[i].address, len);
            }

            snprintf(&mItems[i].abb_address, ABB_NAME_SIZE, "#%d %s", offset + 1, temp_address);
            db_msg("mItems[%d].abb_address:%s", i, mItems[i].abb_address);

        }

        mAddressMenu[i].pMenuText = mItems[i].abb_address;
        db_msg("mAddressMenu[%d]:%s", i, mAddressMenu[i].pMenuText);
        mAddressMenu[i].param = i;
    }
    return strlen(mAddressMenu[0].pMenuText);
}

static int MultiAddressInit(int type) {
    int ret = 0;
	
    mCoinType = type;
    ret = wallet_getHDNode(mCoinType, addr_uname, &mHDNode);
    if (ret == -404) {
        unsigned char passhash[PASSWD_HASHED_LEN] = {0};
        ret = passwdKeyboard(0, "Enter PIN Code", PIN_CODE_VERITY, passhash, PASSKB_FLAG_RANDOM);
        //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        db_msg("passwdKeyboard:%d", ret);
        if (ret < 0) {
            memzero(passhash, sizeof(passhash));
            db_error("input passwd ret:%d", ret);
            return -2;
        } else if (ret == RETURN_DISP_MAINPANEL) {
            memzero(passhash, sizeof(passhash));
            return RETURN_DISP_MAINPANEL;
        }
        ret = wallet_genDefaultPubHDNode(passhash, mCoinType, addr_uname);
        memzero(passhash, sizeof(passhash));
        if (ret == 0) { //read again
            ret = wallet_getHDNode(mCoinType, addr_uname, &mHDNode);
        }
    }
    if (ret != 0) {
        db_error("get hdnode false type:%d uname:%s ret:%d", mCoinType, addr_uname, ret);
        dialog_error3(0, -402, "Addr generated failed.");
        return -3;
    }
    if (!GLobal_PIN_Passed) { //check passwd here,skip input passwd 2 times
        if (checkPasswdKeyboard(0, "Enter PIN Code", PASSKB_FLAG_RANDOM) != 0) {
            db_msg("checkPasswdKeyboard err");
            return -4;
        }
    }

    const CoinConfig *coinConfig = getCoinConfig(mCoinType, addr_uname);
    if (!coinConfig) {
        db_error("get icoinConfig failed");
        return -5;
    }
    int bitcoin_max_index = 0;
    if (coinConfig) {
        bitcoin_max_index = storage_get_coin_max_index(wallet_AccountId(), coinConfig->id);
    }
    db_msg("bitcoin_max_index:%d", bitcoin_max_index);
    if (bitcoin_max_index > 0) {
        max_btc_address_size = bitcoin_max_index + 11;
    } else {
        max_btc_address_size = 11;
    }
    max_btc_address_0ffset = ((max_btc_address_size / MULTI_PAGE_SIZE) * MULTI_PAGE_SIZE);
    max_btc_address_0ffset = max_btc_address_size % MULTI_PAGE_SIZE == 0 ? max_btc_address_0ffset - MULTI_PAGE_SIZE : max_btc_address_0ffset;
    mViewOffet = 0;
    db_msg("max_btc_address_size:%d coinConfig->id:%d addr_uname:%s max_btc_address_0ffset:%d", max_btc_address_size, coinConfig->id, addr_uname, max_btc_address_0ffset);
    return refreshAddressList();
}

int MultiAddressWin(type_uname *param) {
    type_uname *p;
    p = (type_uname *) param;
    if (!p) {
        return -1;
    }
    symbol = p->symbol;

    if (p->type != 1) {
        db_error("coin type is not 1");
        return -2;
    }
    db_msg("MultiAddressWin type:%x,uname:%s p->symbol:%s p->chain_name:%s", p->type, p->uname, p->symbol, p->chain_name);

    addr_uname = p->uname;
    int ret = MultiAddressInit(p->type);
    if (ret <= 0 || ret == RETURN_DISP_MAINPANEL) {
        db_error("init err -> ret:%d", ret);
        return ret;
    }

    int curInx = 0;
    int page_size = 0;

    while (1) {
        db_msg("mViewOffet + MULTI_PAGE_SIZE:%d max_btc_address_size:%d", mViewOffet + MULTI_PAGE_SIZE, max_btc_address_size);
        page_size = mViewOffet + MULTI_PAGE_SIZE > max_btc_address_size ? max_btc_address_size % MULTI_PAGE_SIZE : MULTI_PAGE_SIZE;
        // ret = gui_show_rich_menu(symbol ? symbol : p->chain_name, MENU_LIST | MENU_ICON_NUM | MENU_ONCE, page_size, curInx, mAddressMenu);
        ret = gui_show_rich_menu_with_navi(symbol ? symbol : p->chain_name,
                        MENU_LIST | MENU_ICON_NUM | MENU_ONCE,
                        page_size, curInx, mAddressMenu, INFO_OK,
                        INFO_BACK, DIRECTION_ICON_UP_AND_DOWN, EVENT_KEY_F1);
        db_msg("gui_show_rich_menu ret:%x", ret);
        if (ret == EVENT_NEXT_MENU) {
            if (mViewOffet < max_btc_address_0ffset) {
                mViewOffet = mViewOffet + MULTI_PAGE_SIZE;
            } else {
                mViewOffet = 0;
            }
            curInx = 0;
        } else if (ret == EVENT_LAST_MENU) {
            if (mViewOffet >= MULTI_PAGE_SIZE) {
                mViewOffet = mViewOffet - MULTI_PAGE_SIZE;
                curInx = MULTI_PAGE_SIZE - 1;
            } else {
                mViewOffet = max_btc_address_0ffset;
                curInx = max_btc_address_size % MULTI_PAGE_SIZE > 0 ? max_btc_address_size % MULTI_PAGE_SIZE - 1 : MULTI_PAGE_SIZE - 1;
            }
        } else if (ret == RETURN_DISP_MAINPANEL || ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else {
            break;
        }
        ret = refreshAddressList();
        if (ret <= 0) {
            db_error("refreshAddressList failed ret:%d", ret);
            break;
        }
    }

    return 0;
}
