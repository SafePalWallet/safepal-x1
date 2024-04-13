#define LOG_TAG "CoinsWin"

#include "coin_util.h"
#include "ex_types.h"
#include "gui_sdk.h"
#include "debug.h"
#include "global.h"
#include "CoinsWin.h"
#include "CoinDetailWin.h"
#include "gui_event.h"
#include "resource.h"
#include "storage_manager.h"
#include "gui_api.h"
#include "AddressTypeWin.h"
#include "coin_config.h"
#include "common_core.h"

#define ITEM_BUFFER_SIZE 3
#define COIN_NAME_LEN 18
#define FLAG_HIDE 0x1
#define CLEAR_FLAG(x, flag)        ((x) &~(flag))

static int mViewOffet;
static int mViewTotal;
static int mItemTotal;
static int mEditMode;
static DBCoinInfo mItems[ITEM_BUFFER_SIZE];
static type_uname mTypeUname[ITEM_BUFFER_SIZE];
static const char mCoinName[ITEM_BUFFER_SIZE][COIN_NAME_LEN];

static int changeState(int old_data);
static int addressWin(int param);

static MENU_SET_CFG mCoinMenu[ITEM_BUFFER_SIZE] = {
        {ID_NONE, VAL_OFF, SUB_ON, NULL, addressWin, 0},
        {ID_NONE, VAL_OFF, SUB_ON, NULL, addressWin, 0},
        {ID_NONE, VAL_OFF, SUB_ON, NULL, addressWin, 0},
        // {ID_NONE, VAL_OFF, SUB_ON, NULL, addressWin, 0},
};


static MENU_SET_CFG mCoinEditMenu[ITEM_BUFFER_SIZE] = {
        {ID_NONE, VAL_ON, SUB_OFF, NULL, changeState, 0},
        {ID_NONE, VAL_ON, SUB_OFF, NULL, changeState, 0},
        {ID_NONE, VAL_ON, SUB_OFF, NULL, changeState, 0},
        // {ID_NONE, VAL_ON, SUB_OFF, NULL, changeState, 0},
};

static int changeState(int old_data) {
    int selectindex = gui_sdk_menu_get_index();

    if (selectindex >= ITEM_BUFFER_SIZE) {
        db_error("should not run there selectindex:%d", selectindex);
        return -1;
    }

    if (old_data) {
        mItems[selectindex].flag |= FLAG_HIDE;
    } else {
        mItems[selectindex].flag = CLEAR_FLAG(mItems[selectindex].flag, FLAG_HIDE);
    }
    db_msg("selectindex:%d,old_data:%d,flag:%d", selectindex, old_data, mItems[selectindex].flag);
    storage_set_coin_flag(mItems[selectindex].type, mItems[selectindex].uname, mItems[selectindex].flag);

    return (mCoinEditMenu[selectindex].param = old_data ? 0 : 1);
}

const char *getTypeUname(uint8_t type, char symbol[], char uname[], cstring *tx_str) {
    cstr_clean(tx_str);
    int ret = cstr_append_buf(tx_str, symbol, strlen(symbol));
    if (ret != 1) {
        db_error("tx_str add symbol err");
        return NULL;
    }

    if (strcmp(uname, "OETH") != 0 &&
        strcmp(uname, "ARETH") != 0 &&
        strcmp(uname, "AURORAETH") != 0 ) {
        ret = cstr_append_buf(tx_str, "(", 1);
        if (ret != 1) {
            db_error("tx_str add ( err");
            return NULL;
        }
    }

    const char *name = NULL;
    if (type == COIN_TYPE_BRC20) {
        name = "BRC20";
    } else {
        const CoinConfig *coinConfig = getCoinConfig(type, uname);
        if (coinConfig == NULL) {
            coinConfig = getCoinConfigForMainType(type);
        }

        if (coinConfig == NULL) {
            db_error("coinConfig null");
            return NULL;
        }
    
        if (coinConfig->type == COIN_TYPE_ERC20 || (coinConfig->type == COIN_TYPE_ETH && strcmp(symbol, "ETH"))) {
            name = "ERC20";
        } else if (coinConfig->type == COIN_TYPE_POLKADOT && !strcmp(symbol, "KSM")) {
            name = "Polkadot";
        } else if (coinConfig->type == COIN_TYPE_VET) {
            name = "VeChain";
        } else if (coinConfig->type == COIN_TYPE_TRX) {
            name = "Tron";
        } else if (coinConfig->type == COIN_TYPE_TRC10) {
            name = "TRC10";
        } else if (coinConfig->type == COIN_TYPE_TRC20) {
            name = "TRC20";
        } else if (coinConfig->type == COIN_TYPE_ZKFAIR) {
            name = "ZKFair";
        } else if (!strcmp(coinConfig->name, "BNB")) {
            name = "BEP2";
        } else if (!strcmp(coinConfig->name, "BNB(BEP20)")) {
            name = "BEP20";
        } else if (!strcmp(coinConfig->name, "MATIC(Polygon)")) {
            name = "Polygon";
        } else if (!strcmp(coinConfig->name, "Huobi(HRC20)")) {
            name = "HRC20";
        } else if (!strcmp(coinConfig->name, "Ether(Boba)")) {
            name = "Boba";
        } else if (!strcmp(coinConfig->name, "GLMR(Moonbeam)")) {
            name = "Moonbeam";
        } else if (!strcmp(coinConfig->name, "xDAI(Gnosis)")) {
            name = "Gnosis";
        } else {
            name = coinConfig->name;
        }
    }

    if (name == NULL) {
        db_error("name NULL");
        return NULL;
    }

    if (strcmp(uname, "OETH") != 0 &&
        strcmp(uname, "ARETH") != 0 &&
        strcmp(uname, "AURORAETH") != 0 ) {
        ret = cstr_append_buf(tx_str, name, strlen(name));
        if (ret != 1) {
            db_error("tx_str add name err");
            return NULL;
        }

        ret = cstr_append_buf(tx_str, ")\0", 1);
        if (ret != 1) {
            db_error("tx_str add name err");
            return NULL;
        }
    }

    db_msg("tx_str:%s name:%s", tx_str->str, name);

    return name;
}

static int addressWin(int param) {
    type_uname *p;
    p = (type_uname *) param;
    if (!p) {
        return -1;
    }
    db_msg("jumpTo type:%x,uname:%s symbol:%s", p->type, p->uname, p->symbol);

    if (IS_BTC_COIN_TYPE(p->type) || p->type == COIN_TYPE_SOLANA ||  p->type == COIN_TYPE_BRC20) {
        db_msg("jumpTo btc or sol win");
        return AddressTypeWin(param);
    } else {
        return CoinDetailWin(param);
    }
}

static int updateItemTotal() {
    if (mEditMode) {
        mItemTotal = storage_getCoinsCount(0);
    } else {
        mItemTotal = storage_getCoinsCount(1);
    }
    db_msg("item total:%d mEditMode:%d", mItemTotal, mEditMode);
    return mItemTotal;
}

static int refreshItemList(int init_select) {
    int i = 0, j = 0, cnt = 0, ret = 0;
    int show_switch = 0;

    if (mViewOffet < 0 || mViewOffet >= mItemTotal) mViewOffet = 0;
    if (mEditMode) {
        mViewTotal = storage_queryCoinInfo(&mItems[0], ITEM_BUFFER_SIZE, mViewOffet, 0);
    } else {
        mViewTotal = storage_queryCoinInfo(&mItems[0], ITEM_BUFFER_SIZE, mViewOffet, 1);
    }
    db_msg("view offset:%d total:%d txtotal:%d", mViewOffet, mViewTotal, mItemTotal);
    if (mViewTotal < 1) {
        if (mViewTotal < 0) {
            mViewTotal = 0;
        }
        //mListView->clean();

        if (mItemTotal && mViewOffet) { // query error row change?
            mViewOffet = 0;
            updateItemTotal();
            if (mItemTotal > 0) {
                db_msg("reflush sign history list");
                refreshItemList(0);
            }
        }
        return -1;
    }

    if (mEditMode) {
        for (i = 0; i < mViewTotal; i++) {
            mCoinEditMenu[i].pMenuText = strlen(mItems[i].name) < 14 ? mItems[i].name : mItems[i].symbol;
            db_msg("mCoinEditMenu[%d]:%s,flag:%d", i, mCoinEditMenu[i].pMenuText, mItems[i].flag);
            if (mItems[i].flag & FLAG_HIDE) {
                mCoinEditMenu[i].param = 0;//off
            } else {
                mCoinEditMenu[i].param = 1;//on
            }
        }
    } else {
        cstring *tx_str = cstr_new_sz(10);
        const char *name = NULL;
        GLobal_Is_Coin_EVM_Category = 0;
        for (i = 0; i < mViewTotal; i++) {
            db_msg("name:%s symbol:%s, flag:%#x", mItems[i].name, mItems[i].symbol, mItems[i].flag);
            if ((!IS_VALID_COIN_TYPE(mItems[i].type)) && (mItems[i].flag & DB_FLAG_UNIVERSAL_EVM)) {
                cstr_clean(tx_str);
                cstr_append_buf(tx_str, mItems[i].symbol, strlen(mItems[i].symbol));
                cstr_append_buf(tx_str, "(", 1);
                cstr_append_buf(tx_str, mItems[i].name, strlen(mItems[i].name));
                cstr_append_buf(tx_str, ")\0", 1);
                name = mItems[i].name;
                GLobal_Is_Coin_EVM_Category = 1;
            } else {
                name = getTypeUname(mItems[i].type, mItems[i].symbol, mItems[i].uname, tx_str);
            }

            if (name == NULL) {
                db_error("getTypeUname failed");
                cstr_free(tx_str);
                return -6;
            }

            memset(mCoinName[i], 0x0, COIN_NAME_LEN);
            if (tx_str->len >= COIN_NAME_LEN) {
                memcpy(mCoinName[i], tx_str->str, COIN_NAME_LEN - 4);
                memcpy(mCoinName[i] + COIN_NAME_LEN - 4, "..", 2);
                // memcpy(mCoinName[i] + COIN_NAME_LEN - 2, '\0\0', 2);
            } else {
                memcpy(mCoinName[i], tx_str->str, tx_str->len);
            }
            db_msg("mCoinName[%d]:%s", i, tx_str->str);
            mCoinMenu[i].pMenuText = (char *)mCoinName[i];
            db_msg("mCoinMenu[%d]:%s name:%s symbol:%s type:%d", i, mCoinMenu[i].pMenuText, mItems[i].name,
                   mItems[i].symbol, mItems[i].type);

            memset(&mTypeUname[i], 0x0, sizeof(type_uname));
            mTypeUname[i].type = mItems[i].type;
            strncpy(mTypeUname[i].uname, mItems[i].uname, sizeof(mTypeUname[i].uname));
            strncpy(mTypeUname[i].chain_name, name, sizeof(mTypeUname[i].chain_name));
            if (tx_str->len >= COIN_UNAME_BUFFSIZE) {
                memcpy(mTypeUname[i].symbol, tx_str->str, COIN_UNAME_BUFFSIZE);
            } else {
                memcpy(mTypeUname[i].symbol, tx_str->str, tx_str->len);
            }
            mCoinMenu[i].param = (uint32_t) & mTypeUname[i];
        }

        cstr_free(tx_str);

    }

    return 0;
}

static int CoinWinInit() {
    mViewOffet = 0;
    mViewTotal = 0;
    mItemTotal = 0;
    mEditMode = 0;
    GLobal_Is_Coin_EVM_Category = 0;
    memset(&mItems, 0, sizeof(mItems));
    int refresh = 0, i = 0;
    int ret = 0;
    int m = GLobal_CoinsWin_EditMode ? 1 : 0;
    db_msg("m:%d", m);
    //set_support_long_key(1);
    if (!mItemTotal || Global_Have_New_DBCoin || (mEditMode != m)) {
        mEditMode = m;
        updateItemTotal();
        refresh = 1;
    }

    Global_Have_New_DBCoin = 0;
    if (mItemTotal > 0) {
        if (refresh) {
            ret = refreshItemList(0);
            if (ret == -1) {
                ret = gui_disp_info(NULL, "No Asset", TEXT_ALIGN_CENTER | TEXT_VALIGN_CENTER,
                                   res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                                   EVENT_KEY_F1);
                if (ret == EVENT_KEY_F1) {
                    ret = RETURN_DISP_MAINPANEL;
                } else {
                    ret = -100;
                }
            }
        }
    } else {
        //tips not sign
        ret = gui_disp_info(NULL, "No Asset", TEXT_ALIGN_CENTER | TEXT_VALIGN_CENTER,
                           res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
        if (ret == EVENT_KEY_F1) {
            ret = RETURN_DISP_MAINPANEL;
        } else {
            ret = -100;
        }
    }

    if (ret == -100) {
        if (mEditMode) {
            //changeWindow(WINDOWID_SETTING);
        } else {
            //changeWindow(WINDOWID_MAINPANEL);
        }
    }

    return ret;
}

int CoinsWin(int param) {
    int ret = 0, curInx = 0;

    ret = CoinWinInit();
    if (ret != 0) {
        db_error("init error");
        return ret;
    }

    int max_offset = ((mItemTotal - 1) / ITEM_BUFFER_SIZE) * ITEM_BUFFER_SIZE;
    while (1) {
        // ret = gui_show_rich_menu(res_getLabel(LANG_LABEL_ASSETS), MENU_LIST | MENU_ICON_NUM | MENU_ONCE, mViewTotal, curInx,
                        //    mEditMode ? mCoinEditMenu : mCoinMenu);
        ret = gui_show_rich_menu_with_navi(res_getLabel(LANG_LABEL_ASSETS),
                        MENU_LIST | MENU_ICON_NUM | MENU_ONCE,
                        mViewTotal, curInx, mEditMode ? mCoinEditMenu : mCoinMenu, INFO_OK,
                        INFO_BACK, DIRECTION_ICON_UP_AND_DOWN, EVENT_KEY_F1);
                        
        if (ret == EVENT_NEXT_MENU) {
            if (mItemTotal > ITEM_BUFFER_SIZE) {//next page
                db_msg("down mViewOffet:%d mViewTotal:%d mItemTotal:%d try page down", mViewOffet, mViewTotal,
                       mItemTotal);
                if ((mViewOffet + mViewTotal) < mItemTotal) {
                    mViewOffet += ITEM_BUFFER_SIZE;
                    refreshItemList(0);
                } else if ((mViewOffet + mViewTotal) == mItemTotal) {//circle
                    mViewOffet = 0;
                    refreshItemList(0);
                } 
            } 
            curInx = 0;
        } else if (ret == EVENT_LAST_MENU) {
            db_msg("up mViewOffet:%d mViewTotal:%d mItemTotal:%d try page down", mViewOffet, mViewTotal, mItemTotal);
            if (mItemTotal > ITEM_BUFFER_SIZE) {//last page
                if (mViewOffet > 0) {
                    mViewOffet -= ITEM_BUFFER_SIZE;
                    refreshItemList(0);
                } else if (mViewOffet == 0) {//circle
                    mViewOffet = max_offset;
                    db_msg("mViewOffet:%d max_offset:%d", mViewOffet, max_offset);
                    refreshItemList(0);
                } 
            } 
            curInx = mViewTotal - 1;
        } else if (ret == RETURN_DISP_MAINPANEL || ret == EVENT_KEY_F1) {
            return RETURN_DISP_MAINPANEL;
        } else {
            break;
        }
    }

    return ret;
}


