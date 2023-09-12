#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Binance/bnc_sign.c"

#endif

enum {
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_PAYFROM_TITLE,
	TXS_LABEL_PAYFROM_ADDRESS,
	TXS_LABEL_PAYTO_TITLE,
	TXS_LABEL_PAYTO_ADDRESS,
	TXS_LABEL_MEMO_TITLE,
	TXS_LABEL_MEMO_CONTENT,
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
	BncTransRequest *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -1;
	}

	const CoinConfig *coinConfig = getCoinConfig(COIN_TYPE_BNC, "BNB");
	if (NULL == coinConfig) {
		db_error("not support type:%d", COIN_TYPE_BNC);
		return -181;
	}

	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);

	int coin_type = COIN_TYPE_BNC;
	const char *coin_uname = msg->token.uname;
	const char *name = msg->token.name;
	const char *symbol = msg->token.symbol;
	int64_t send_amount = msg->send_to.amount;
	double send_value = ((double) send_amount) / 100000000;

	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->total_height = 2 * SCREEN_HEIGHT;
	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = name;
	// view->coin_symbol = symbol;
	view->coin_symbol = res_getLabel(LANG_LABEL_SEND);


	db_msg("get send_value:%.8lf str:%s", send_value, tmpbuf);
	snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", send_value);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

	// strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
	// snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);
	// snprintf(tmpbuf, sizeof(tmpbuf), "\xe2\x89\x88%s%.2f", money_symbol, ex_rate * send_value);
	// view_add_txt(TXS_LABEL_TOTAL_MONEY, tmpbuf);
	// strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

    view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, "BNB(BEP2)");

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, requestIsTestNet(msg));
	db_msg("my address ret:%d addr:%s", ret, tmpbuf);
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	bnc_gen_address(tmpbuf, msg->send_to.address.bytes, requestIsTestNet(msg));
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

	if (!is_empty_string(msg->memo)) {
		//mTotalHeight = 3 * mScreenHeight;
		//rect.y += mScreenHeight;
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