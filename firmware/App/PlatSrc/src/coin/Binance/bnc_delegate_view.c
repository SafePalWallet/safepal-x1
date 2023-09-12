#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Binance/bnc_delegate.c"

#endif

enum {
    TXS_LABEL_TOTAL_VALUE,
    TXS_LABEL_TOTAL_MONEY,
    TXS_LABEL_FEED_TITLE,
    TXS_LABEL_FEED_VALUE,
    TXS_LABEL_PAYFROM_TITLE,
    TXS_LABEL_PAYFROM_ADDRESS,
    TXS_LABEL_PAYTO_TITLE,
    TXS_LABEL_PAYTO_ADDRESS,
    TXS_LABEL_MAXID,
};

static int on_sign_show(void *session, DynamicViewCtx *view) {
    char tmpbuf[128];
    coin_state *s = (coin_state *) session;
    if (!s) {
        db_error("invalid session");
        return -1;
    }

    int ret;
    BncDelegateRequest *msg = &s->req;
    DBTxCoinInfo *db = &view->db;
    memset(db, 0, sizeof(DBTxCoinInfo));

    if (proto_check_exchange(&msg->exchange) != 0) {
        db_error("invalid exchange");
        return -1;
    }

    double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
    const char *money_symbol = proto_get_money_symbol(&msg->exchange);

    int coin_type = COIN_TYPE_BNC;
    const char *coin_uname = msg->token.uname;
    const char *name = msg->token.name;
    const char *symbol = msg->token.symbol;
    int64_t send_amount = msg->amount;
    double send_value = ((double) send_amount) / 100000000;

    db->coin_type = coin_type;
    strlcpy(db->coin_name, name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

    view->total_height = 2 * SCREEN_HEIGHT;
    view->coin_type = coin_type;
    view->coin_uname = coin_uname;
    view->coin_name = name;
    view->coin_symbol = symbol;

    snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", send_value);
    view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
    strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
    snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);

    snprintf(tmpbuf, sizeof(tmpbuf), "\xe2\x89\x88%s%.2f", money_symbol, ex_rate * send_value);
    view_add_txt(TXS_LABEL_TOTAL_MONEY, tmpbuf);

    strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

    db_msg("msg->validator_dst_name:%s,msg->validator_src_name:%s", msg->validator_dst_name, msg->validator_src_name);

    view_add_txt(TXS_LABEL_FEED_TITLE, "Validator:");
    if (msg->validator_dst_name) {
        view_add_txt(TXS_LABEL_FEED_VALUE, msg->validator_dst_name);
    } else {
        view_add_txt(TXS_LABEL_FEED_VALUE, msg->validator_src_name);
    }

    view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
    view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
    memzero(tmpbuf, sizeof(tmpbuf));
    if (msg->type == BNC_DELEGATE) {
        ret = bnc_gen_address(tmpbuf, msg->delegator_addr.bytes, requestIsTestNet(msg));
        view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);
        memzero(tmpbuf, sizeof(tmpbuf));
        bnc_gen_validator_address(tmpbuf, msg->validator_dst_addr.bytes);
        view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);
    } else if (msg->type == BNC_UNDELEGATE) {
        ret = bnc_gen_validator_address(tmpbuf, msg->validator_dst_addr.bytes);
        view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);
        memzero(tmpbuf, sizeof(tmpbuf));
        bnc_gen_address(tmpbuf, msg->delegator_addr.bytes, requestIsTestNet(msg));
        view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);
    } else if (msg->type == BNC_REDELEGATE) {
        ret = bnc_gen_address(tmpbuf, msg->delegator_addr.bytes, requestIsTestNet(msg));
        view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);
        memzero(tmpbuf, sizeof(tmpbuf));
        bnc_gen_validator_address(tmpbuf, msg->validator_dst_addr.bytes);
        view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);
    }

    //save coin info
    if (view->msg_from == MSG_FROM_QR_APP) {
        if (!storage_isCoinExist(coin_type, coin_uname)) {
            DBCoinInfo dbinfo;
            memset(&dbinfo, 0, sizeof(dbinfo));
            dbinfo.type = (uint8_t) coin_type;
            dbinfo.curv = coin_get_curv_id(coin_type, coin_uname);
            dbinfo.decimals = 8;
            strncpy(dbinfo.uname, coin_uname, COIN_UNAME_MAX_LEN);
            strncpy(dbinfo.name, name, COIN_NAME_MAX_LEN);
            strncpy(dbinfo.symbol, symbol, COIN_SYMBOL_MAX_LEN);
            storage_save_coin_dbinfo(&dbinfo);
        }
    }
    return 0;
}

#endif