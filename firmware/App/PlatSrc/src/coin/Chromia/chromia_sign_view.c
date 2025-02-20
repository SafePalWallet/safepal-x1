#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Chromia/chromia_sign.c"

#endif

#include "coin_util_hw.h"
#include <ctype.h>

void toLowerCase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char) str[i]);
    }
}

static int on_sign_show(void *session, DynamicViewCtx *view) {
    char tmpbuf[128] = {0};
    int coin_type = 0;
    const char *coin_uname = NULL;
    const char *name = NULL;
    const char *symbol = NULL;
    uint8_t coin_decimals = 0;
    int ret = 0;

    coin_state *s = (coin_state *) session;
    if (!s) {
        db_error("invalid session");
        return -1;
    }

    ChrSignTxReq *msg = &s->req;
    DBTxCoinInfo *db = &view->db;
    memset(db, 0, sizeof(DBTxCoinInfo));

    if (is_empty_string(msg->coin.uname)) {
        db_error("invalid coin.uname:%s", msg->coin.uname);
        return -2;
    }

    coin_type = msg->coin.type;
    coin_uname = msg->coin.uname;

    if (msg->operation_type == CHR_TYPE_TRANSFER) {
        name = msg->coin.uname;
        symbol = msg->coin.uname;
        coin_decimals = msg->token.decimals;
    } else if ((char) msg->operation_type == CHR_TYPE_REGISTER) { // token
        name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
        symbol = "REGISTER";
    } else {
        db_error("invalid type");
        return -3;
    }

    if ((char) msg->operation_type == CHR_TYPE_TRANSFER) {
        view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
        if (proto_check_exchange(&msg->exchange) != 0) {
            db_error("invalid exchange");
            return -4;
        }

        view_add_txt(0, msg->action.sendCoins.amount);
        view_add_txt(0, symbol);
        view_add_txt(0, "Chain:");
        view_add_txt(0, "Chromia");
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
        // view_add_txt(0, msg->action.sendCoins.from);
        memset(tmpbuf, 0x00, sizeof(tmpbuf));
        memcpy(tmpbuf, msg->action.sendCoins.from, 64);
        toLowerCase(tmpbuf);
        view_add_txt(0, tmpbuf);

        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
        // view_add_txt(0, msg->action.sendCoins.to);
        memset(tmpbuf, 0x00, sizeof(tmpbuf));
        memcpy(tmpbuf, msg->action.sendCoins.to + 2, 64);
        toLowerCase(tmpbuf);
        view_add_txt(0, tmpbuf);

        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        view_add_txt(0, "0");
        view_add_txt(0, "CHR");
    } else if ((char) msg->operation_type == CHR_TYPE_REGISTER) {
        view->coin_symbol = res_getLabel(LANG_LABEL_SIGN_TRANSACTION);
        db->tx_type = TX_TYPE_APP_APPROVAL;
        view_add_txt(0, "Chain:");
        view_add_txt(0, "Chromia");
        view_add_txt(0, "BlockchainRID:");
        view_add_txt(0, msg->action.registerAccount.blockchainRid);
    }

    db->coin_type = coin_type;
    strlcpy(db->coin_name, name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));
    view->coin_type = coin_type;
    view->coin_uname = coin_uname;
    view->coin_name = name;

    // save coin info
    if (view->msg_from == MSG_FROM_QR_APP) {
        if (!storage_isCoinExist(coin_type, coin_uname)) {
            DBCoinInfo dbinfo;
            memset(&dbinfo, 0, sizeof(dbinfo));
            dbinfo.type = (uint8_t) coin_type;
            dbinfo.curv = coin_get_curv_id(coin_type, coin_uname);
            dbinfo.decimals = coin_decimals;
            strncpy(dbinfo.uname, coin_uname, COIN_UNAME_MAX_LEN);
            strncpy(dbinfo.name, name, COIN_NAME_MAX_LEN);
            strncpy(dbinfo.symbol, symbol, COIN_SYMBOL_MAX_LEN);
            storage_save_coin_dbinfo(&dbinfo);
        }
    }
    return 0;
}

#endif
