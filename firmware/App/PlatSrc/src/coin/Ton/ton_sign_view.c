#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Ton/ton_sign.c"

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

    TonSignTxReq *msg = &s->req;
    DBTxCoinInfo *db = &view->db;
    memset(db, 0, sizeof(DBTxCoinInfo));

    if (is_empty_string(msg->coin.uname)) {
        db_error("invalid coin.uname:%s", msg->coin.uname);
        return -1;
    }

    coin_type = msg->coin.type;
    coin_uname = msg->coin.uname;

    if ((char) msg->operation_type == TON_TRANSFER) {
        if (strcmp(coin_uname, "TON") == 0) {
            config = getCoinConfig(coin_type, coin_uname);
            if (!config) {
                db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
                name = msg->coin.uname;
                symbol = msg->coin.uname;
                coin_decimals = 9;
            } else {
                name = config->name;
                symbol = config->symbol;
                coin_decimals = config->decimals;
            }
        } else {//token
            if (is_empty_string(msg->token.name) || is_empty_string(msg->token.symbol)) {
                db_error("invalid token name:%s or symbol:%s", msg->token.name, msg->token.symbol);
                return -2;
            }
            db_msg("msg->token.name:%s", msg->token.name);
            db_msg("msg->token.symbol:%s", msg->token.symbol);
            db_msg("msg->token.decimals:%d", msg->token.decimals);

            name = msg->token.name;
            symbol = msg->token.symbol;
            coin_decimals = msg->token.decimals;
        }

    } else if ((char) msg->operation_type == TON_DAPP) {
        name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);

        if (is_empty_string(msg->action.dapp.app_name)) {
            db_error("invalid action.dapp.app_name:%s", msg->action.dapp.app_name);
            return -3;
        }

        symbol = msg->action.dapp.app_name;
    } else if ((char) msg->operation_type == TON_MSG) {
        name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);

        if (is_empty_string(msg->action.msg.app_name)) {
            db_error("invalid action.msg.app_name:%s", msg->action.msg.app_name);
            return -3;
        }

        symbol = msg->action.msg.app_name;
    }

    if ((char) msg->operation_type == TON_TRANSFER) {
        view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
        if (proto_check_exchange(&msg->exchange) != 0) {
            db_error("invalid exchange");
            return -4;
        }

        ret = bignum2double((const unsigned char *) msg->action.sendCoins.amount.bytes, msg->action.sendCoins.amount.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
        strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
        view_add_txt(0, tmpbuf);
        view_add_txt(0, symbol);
        view_add_txt(0, "Chain:");
        view_add_txt(0, "Toncoin");
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
        view_add_txt(0, msg->action.sendCoins.from);
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
        view_add_txt(0, msg->action.sendCoins.to);
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        ret = bignum2double((const unsigned char *) msg->action.sendCoins.fee.bytes, msg->action.sendCoins.fee.size, 9, &send_value, tmpbuf, sizeof(tmpbuf));
        view_add_txt(0, tmpbuf);
        view_add_txt(0, "TON");
    } else if ((char) msg->operation_type == TON_DAPP) {
        view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);

        view_add_txt(0, "DApp:");
        view_add_txt(0, symbol);

        view_add_txt(0, "Chain:");
        view_add_txt(0, "Toncoin");

        view_add_txt(0, "Data:");
        db->tx_type = TX_TYPE_APP_SIGN_MSG;
        view_add_txt(0, msg->action.dapp.content);
    } else if ((char) msg->operation_type == TON_MSG) {
        view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);

        view_add_txt(0, "DApp:");
        view_add_txt(0, symbol);

        view_add_txt(0, "Chain:");
        view_add_txt(0, "Toncoin");

        view_add_txt(0, "Data:");
        db->tx_type = TX_TYPE_APP_SIGN_MSG;
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.msg.message, 52, 20);
        view_add_txt(0, tmpbuf);
    } else if ((char) msg->operation_type == TON_NFT) {
        name = msg->action.sendCoins.app_name;
        symbol = msg->action.sendCoins.app_name;

        view->coin_symbol = res_getLabel(LANG_LABEL_SEND_NFT);
        view_add_txt(0, symbol);

        view_add_txt(0, "Contract Address");
        memset(tmpbuf, 0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.sendCoins.contract, 8, 8);
        view_add_txt(0, tmpbuf);

        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
        omit_string(tmpbuf, tmpbuf, 26, 11);
        view_add_txt(0, tmpbuf);

        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.sendCoins.to, 26, 11);
        view_add_txt(0, tmpbuf);

        coin_decimals = 9;
        view_add_txt(0, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        ret = bignum2double((const unsigned char *) msg->action.sendCoins.fee.bytes,
                            msg->action.sendCoins.fee.size, coin_decimals, &send_value, tmpbuf,
                            sizeof(tmpbuf));
        db_msg("fee send_value:%.8lf", send_value);
        snprintf(tmpbuf, sizeof(tmpbuf), "%s TON", tmpbuf);
        db_msg("feed value:%s", tmpbuf);
        view_add_txt(0, tmpbuf);

        view_add_txt(0, "Chain:");
        view_add_txt(0, "Toncoin");
    }

    if ((char) msg->operation_type == TON_TRANSFER && !is_empty_string(msg->action.sendCoins.payload)) {
        db_msg("memo:%s", msg->action.sendCoins.payload);
        view->total_height = 3 * SCREEN_HEIGHT;
        if (is_printable_str(msg->action.sendCoins.payload)) {
            view_add_txt(0, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
            view_add_txt(0, msg->action.sendCoins.payload);
        } else {
            view_add_txt(0, res_getLabel(LANG_LABEL_TX_MEMO_HEX_TITLE));
            ret = strlen(msg->action.sendCoins.payload);
            if (ret * 2 < (int) sizeof(tmpbuf)) {
                bin_to_hex((const unsigned char *) msg->action.sendCoins.payload, ret, tmpbuf);
                view_add_txt(0, tmpbuf);
            } else {
                char *hex = (char *) malloc((ret + 1) * 2);
                if (hex) {
                    memset(hex, 0, (ret + 1) * 2);
                    bin_to_hex((const unsigned char *) msg->action.sendCoins.payload, ret, hex);
                    view_add_txt(0, hex);
                    free(hex);
                }
            }
        }
    }

    db->coin_type = coin_type;
    strlcpy(db->coin_name, name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));
    view->coin_type = coin_type;
    view->coin_uname = coin_uname;
    view->coin_name = name;

    //save coin info
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