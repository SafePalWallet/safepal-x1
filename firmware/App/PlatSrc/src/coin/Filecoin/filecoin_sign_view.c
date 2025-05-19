#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Filecoin/filecoin_sign.c"

#endif

#include "coin_util_hw.h"

static int on_sign_show(void *session, DynamicViewCtx *view) {
    char tmpbuf[128];
    int coin_type = 0;
    const char *coin_uname = NULL;
    const char *name = NULL;
    const char *symbol = NULL;
    double send_value = 0;
    uint8_t coin_decimals = 0;
    const CoinConfig *config = NULL;
    int ret = 0, len = 0;

    coin_state *s = (coin_state *) session;
    if (!s) {
        db_error("invalid session");
        return -1;
    }

    FilecoinSignTxReq *msg = &s->req;
    DBTxCoinInfo *db = &view->db;
    memset(db, 0, sizeof(DBTxCoinInfo));

    if (is_empty_string(msg->coin.uname)) {
        db_error("invalid coin.uname:%s", msg->coin.uname);
        return -2;
    }

    coin_type = msg->coin.type;
    coin_uname = msg->coin.uname;

    if (msg->operation_type == FIL_TRANSFER) {
        config = getCoinConfig(coin_type, coin_uname);
        if (!config) {
            db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
            name = msg->coin.uname;
            symbol = msg->coin.uname;
            coin_decimals = 18;
        } else {
            name = config->name;
            symbol = config->symbol;
            coin_decimals = config->decimals;
        }
    } else {
        db_error("invalid type");
        return -3;
    }

    if ((char) msg->operation_type == FIL_TRANSFER) {
        view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
        if (proto_check_exchange(&msg->exchange) != 0) {
            db_error("invalid exchange");
            return -4;
        }

        ret = bignum2double((const unsigned char *) msg->action.sendCoins.value.bytes, msg->action.sendCoins.value.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
        strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
        view_add_txt(0, tmpbuf);
        view_add_txt(0, symbol);
        view_add_txt(0, "Chain:");
        view_add_txt(0, "Filecoin");
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
        view_add_txt(0, msg->action.sendCoins.from);
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
        view_add_txt(0, msg->action.sendCoins.to);
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        ret = bignum2double((const unsigned char *) msg->action.sendCoins.gasFeeCap.bytes, msg->action.sendCoins.gasFeeCap.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
        db_msg("send_value:%.10lf", send_value * msg->action.sendCoins.gasLimit);
        snprintf(tmpbuf, sizeof(tmpbuf), "%.12lf", send_value * msg->action.sendCoins.gasLimit);
        view_add_txt(0, tmpbuf);
        view_add_txt(0, "FIL");
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
