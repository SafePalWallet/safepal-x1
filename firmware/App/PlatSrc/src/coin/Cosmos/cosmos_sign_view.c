#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Cosmos/cosmos_sign.c"

#endif
#include "coin_config.h"

enum {
    TXS_LABEL_TOTAL_VALUE,
    TXS_LABEL_TOTAL_MONEY,
    TXS_LABEL_FEED_TILE,
    TXS_LABEL_FEED_VALUE,
    TXS_LABEL_GAS_LIMIT,
    TXS_LABEL_GAS_PRICE,
    TXS_LABEL_PAYFROM_TITLE,
    TXS_LABEL_PAYFROM_ADDRESS,
    TXS_LABEL_PAYTO_TITLE,
    TXS_LABEL_PAYTO_ADDRESS,
    TXS_LABEL_MEMO_TITLE,
    TXS_LABEL_MEMO_CONTENT,
    TXS_LABEL_APP_MSG_VALUE,
    TXS_LABEL_MAXID,
};

static int on_sign_show(void *session, DynamicViewCtx *view) {
	char tmpbuf[128], buf[128];
    int coin_type = 0;
    const char *coin_uname = NULL;
    const char *name = NULL;
    const char *symbol = NULL;
    double send_value = 0;
    int value = 0, fee = 0, tax = 0, gas = 0;
    int ret;
    uint8_t coin_decimals = 0;
    const CoinConfig *config = NULL;

    coin_state *s = (coin_state *) session;
    if (!s) {
        db_error("invalid session");
        return -1;
    }

    CosmosSignTxReq *msg = &s->req;
    DBTxCoinInfo *db = &view->db;
    memset(db, 0, sizeof(DBTxCoinInfo));

#if 0
    db_msg("-------------------------------");
    db_msg("msg->coin.type:%x", (int) msg->coin.type);
    db_msg("msg->coin.uname:%s", msg->coin.uname);
    db_msg("msg->exchange.amount:%d", (int) msg->exchange.amount);
    db_msg("msg->exchange.currency:%s", msg->exchange.currency);
    db_msg("msg->exchange.symbol:%s", msg->exchange.symbol);
    db_msg("msg->exchange.value:%lld", msg->exchange.value);
    db_msg("msg->account_number:%s", msg->account_number);
    db_msg("msg->chain_id:%s", msg->chain_id);
    db_msg("msg->memo:%s", msg->memo);
    db_msg("msg->general_fee:%s", msg->general_fee);
    db_msg("msg->tax:%s", msg->tax);
    db_msg("msg->token.name:%s", msg->token.name);
    db_msg("msg->token.symbol:%s", msg->token.symbol);

    if ((char) msg->operation_type == OP_TYPE_TRANSFER) {
        db_msg("msg->action.sendCoins.from_address:%s", msg->action.sendCoins.from_address);
        db_msg("msg->action.sendCoins.to_address:%s", msg->action.sendCoins.to_address);
        db_msg("msg->action.sendCoins.amount_n:%d", msg->action.sendCoins.amount_n);
        db_msg("msg->action.sendCoins.amount->amount:%s", msg->action.sendCoins.amount->amount);
        db_msg("msg->token.name:%s", msg->token.name);
    }else if((char)msg->operation_type==OP_TYPE_CW20_TRANSFER){
        db_msg("msg->action.sendC20Coins.type:%s", msg->action.sendC20Coins.type);
        db_msg("msg->action.sendC20Coins.sender:%s", msg->action.sendC20Coins.sender);
        db_msg("msg->action.sendC20Coins.contract:%s", msg->action.sendC20Coins.contract);
        db_msg("msg->action.sendC20Coins.amount:%s", msg->action.sendC20Coins.amount);
        db_msg("msg->action.sendC20Coins.recipient:%s", msg->action.sendC20Coins.recipient);
    } else if ((char) msg->operation_type == OP_TYPE_DAPP) {
        db_msg("msg->action.dapp.app_name:%s", msg->action.dapp.app_name);
        db_msg("msg->action.dapp.message:%s", msg->action.dapp.message);
        db_msg("msg->action.dapp.type:%d", msg->action.dapp.type);
        db_msg("msg->action.dapp.gas:%s", msg->action.dapp.gas);
        db_msg("msg->action.dapp.fee:%s", msg->action.dapp.fee);
    }
    db_msg("--------------------------------");
#endif

    config = getCoinConfigForMainType(msg->coin.type);
    if (!config) {
        db_msg("not config null");
        return -1;
    }

    coin_type = msg->coin.type;
    coin_uname = msg->coin.uname;
    if ((char) msg->operation_type == OP_TYPE_CW20_TRANSFER) {
        if (is_empty_string(msg->token.name) || is_empty_string(msg->token.symbol)) {
            db_error("invalid dtoken name:%s or symbol:%s", msg->token.name, msg->token.symbol);
            return -1;
        }
        name = msg->token.name;
        symbol = msg->token.symbol;
        coin_decimals = msg->token.decimals;
        value = atoi(msg->action.sendC20Coins.amount);
    } else if ((char) msg->operation_type == OP_TYPE_DAPP) {
        name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
        symbol = msg->action.dapp.app_name;
        coin_decimals = 6;
    } else {
        if ((strcmp(msg->coin.uname, "LUNA") == 0) || (strcmp(msg->coin.uname, "ATOM") == 0) || \
            (strcmp(msg->coin.uname, "LUNA2") == 0)) {
            if (!config) {
                db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
                name = msg->coin.uname;
                symbol = msg->coin.uname;
                coin_decimals = 6;
            } else {
                name = config->name;
                symbol = config->symbol;
                coin_decimals = config->decimals;
            }
        } else {//UST(Token)
            name = msg->token.name;
            symbol = msg->token.symbol;
            coin_decimals = msg->token.decimals;
        }
        value = atoi(msg->action.sendCoins.amount->amount);
    }

    if (((char) msg->operation_type == OP_TYPE_TRANSFER) || \
        ((char) msg->operation_type == OP_TYPE_CW20_TRANSFER)) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
        if (proto_check_exchange(&msg->exchange) != 0) {
            db_error("invalid exchange");
            return -1;
        }
        double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
        const char *money_symbol = proto_get_money_symbol(&msg->exchange);

        memset(tmpbuf, 0, sizeof(tmpbuf));
        send_value = proto_coin_real_value(value, coin_decimals);
        snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", send_value);
        strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
        view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, symbol);

        view_add_txt(TXS_LABEL_MAXID, "Chain:");
		view_add_txt(TXS_LABEL_MAXID, config->name);

        view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
        if ((char) msg->operation_type == OP_TYPE_TRANSFER) {
            view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, msg->action.sendCoins.from_address);
            view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
            view_add_txt(TXS_LABEL_PAYTO_ADDRESS, msg->action.sendCoins.to_address);
        } else {
            view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, msg->action.sendC20Coins.sender);
            view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
            view_add_txt(TXS_LABEL_PAYTO_ADDRESS, msg->action.sendC20Coins.recipient);
        }

        //fee
        /*memset(tmpbuf, 0, sizeof(tmpbuf));
        view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        fee = atoi(msg->general_fee);
        format_coin_real_value(tmpbuf, sizeof(tmpbuf), fee, 6);
        view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		// view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);
*/
        if(msg->fee.amount) {
            CosmosAmount *amount = msg->fee.amount;
            if(amount->amount) {
                memset(tmpbuf, 0, sizeof(tmpbuf));
                view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
                fee = atoi(amount->amount);
                format_coin_real_value(tmpbuf, sizeof(tmpbuf), fee, 6);
                view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
                view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);
            }
        }

#if 0
        //snprintf(tmpbuf, sizeof(tmpbuf), "tax:%s", msg->tax);
        //view_add_txt(TXS_LABEL_GAS_LIMIT, tmpbuf);
        if (!is_empty_string(msg->tax)) {
            memset(tmpbuf, 0, sizeof(tmpbuf));
            memset(buf, 0, sizeof(buf));
            tax = atoi(msg->tax);
            if (tax != 0) {
                format_coin_real_value(buf, sizeof(buf), tax, 6);
                // snprintf(tmpbuf, sizeof(tmpbuf), "Tax: %s", buf);
                view_add_txt(TXS_LABEL_GAS_LIMIT, "Tax: ");
                view_add_txt(TXS_LABEL_GAS_LIMIT, buf);
            }
        }
#endif
        strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));
        view->total_height = 2 * SCREEN_HEIGHT;

    } else if ((char) msg->operation_type == OP_TYPE_DAPP) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SIGN_TRANSACTION);
        db->tx_type = TX_TYPE_APP_SIGN_MSG;
        view->total_height = SCREEN_HEIGHT;

        //dapp
		view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
		view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

        view_add_txt(TXS_LABEL_MAXID, "Chain:");
		view_add_txt(TXS_LABEL_MAXID, config->name);

        //from
		view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
		db_msg("my address ret:%d addr:%s", ret, tmpbuf);
		view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);


        view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        view_add_txt(TXS_LABEL_FEED_VALUE, msg->action.dapp.fee);
        // view_add_txt(TXS_LABEL_GAS_LIMIT, msg->action.dapp.gas);
        // view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);

        view_add_txt(TXS_LABEL_APP_MSG_VALUE, "Data:");
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.dapp.message, 52, 20);
        view_add_txt(TXS_LABEL_APP_MSG_VALUE, tmpbuf);
    } else {

    }

    db->coin_type = coin_type;
    strlcpy(db->coin_name, name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

    view->coin_type = coin_type;
    view->coin_uname = coin_uname;
    view->coin_name = name;
    // view->coin_symbol = symbol;

    if (!is_empty_string(msg->memo)) {
        view->total_height = 3 * SCREEN_HEIGHT;
        if (is_printable_str(msg->memo)) {
            view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
            view_add_txt(TXS_LABEL_MEMO_CONTENT, msg->memo);
        } else {
            view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_HEX_TITLE));
            ret = strlen(msg->memo);
            if (ret * 2 < (int) sizeof(tmpbuf)) {
                bin_to_hex((const unsigned char *) msg->memo, ret, tmpbuf);
                view_add_txt(TXS_LABEL_MEMO_CONTENT, tmpbuf);
            } else {
                char *hex = (char *) malloc((ret + 1) * 2);
                if (hex) {
                    memset(hex, 0, (ret + 1) * 2);
                    bin_to_hex((const unsigned char *) msg->memo, ret, hex);
                    view_add_txt(TXS_LABEL_MEMO_CONTENT, hex);
                    free(hex);
                }
            }
        }
    } else {
        // view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
        // view_add_txt(TXS_LABEL_MEMO_CONTENT, "");
    }

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
