#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/VeChain/vet_sign.c"

#endif

#include "coin_util_hw.h"

enum {
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_NFT_ID_TITLE,
	TXS_LABEL_NFT_ID_VALUE,
	TXS_LABEL_NFT_AMOUNT_TITLE,
	TXS_LABEL_NFT_AMOUNT_VALUE,
	TXS_LABEL_FEED_TILE,
	TXS_LABEL_FEED_VALUE,
	TXS_LABEL_GAS_LIMIT,
	TXS_LABEL_GAS_PRICE,
	TXS_LABEL_PAYFROM_TITLE,
	TXS_LABEL_PAYFROM_ADDRESS,
	TXS_LABEL_PAYTO_TITLE,
	TXS_LABEL_PAYTO_ADDRESS,
	TXS_LABEL_DATA_TITLE,
	TXS_LABEL_DATA_CONTENT,
	TXS_LABEL_APPROVE_TOKEN_TITLE,
	TXS_LABEL_APPROVE_TOKEN_VALUE,
	TXS_LABEL_APPROVE_AMOUNT_TITLE,
	TXS_LABEL_APPROVE_AMOUNT_VALUE,
	TXS_LABEL_SIMPLE_FEE_TITLE,
	TXS_LABEL_SIMPLE_FEE_VALUE,
	TXS_LABEL_APP_MSG_VALUE,
	TXS_LABEL_MAXID,
};

static int on_sign_show(void *session, DynamicViewCtx *view) {
	char tmpbuf[256];
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	int ret;
	VetSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	if (msg->clauses_n != 1 || !msg->clauses) {
		db_error("invalid clauses");
		return -101;
	}
	const Clause *clause = msg->clauses;
	memset(db, 0, sizeof(DBTxCoinInfo));
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -102;
	}

	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);

	int coin_type = 0;
	const char *coin_uname = "";
	const char *name = "";
	const char *symbol = "";
	uint8_t coin_decimals = 0;
	uint8_t is_transfer = 0;
	uint8_t is_transfer_from = 0;
	uint8_t trans_token = 0;
	uint8_t detected_data = 0;
	const CoinConfig *config = NULL;
	do {
		detected_data = 1;
		//transfer(address _to, uint256 _value)     //ERC20 MethodID: 0xa9059cbb
		if (clause->to.size == 20 && clause->value.size == 0 && clause->data.size == 68
		    && memcmp(clause->data.bytes, "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {
			is_transfer = 1;
			trans_token = 1;
			break;
		}
		//transferFrom(address src, address dst, uint256 amount) MethodID: 0x23b872dd
		if (clause->to.size == 20 && clause->value.size == 0 && clause->data.size == 100
		    && memcmp(clause->data.bytes, "\x23\xb8\x72\xdd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {
			is_transfer_from = 1;
			trans_token = 1;
			break;
		}
		detected_data = 0;
	} while (0);

	if (msg->coin.type && is_not_empty_string(msg->coin.uname)) {
		config = getCoinConfig(msg->coin.type, msg->coin.uname);
		if (!config) {
			db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
		}
	}
	if (config) {
		name = config->name;
		symbol = config->symbol;
		coin_decimals = config->decimals;
		coin_type = config->type;
		coin_uname = config->uname;
	} else if (trans_token && msg->token.type) {
		if (msg->coin.type && msg->token.type != msg->coin.type) {
			db_error("invalid coin.type:%d token.type:%d", msg->coin.type, msg->token.type);
			return -1;
		}
		if (is_empty_string(msg->token.name) || is_empty_string(msg->token.symbol)) {
			db_error("invalid dtoken name:%s or symbol:%s", msg->token.name, msg->token.symbol);
			return -1;
		}
		if (msg->token.decimals < 0 || msg->token.decimals > 40) {
			db_error("invalid decimals:%d", msg->token.decimals);
			return -1;
		}
		name = msg->token.name;
		symbol = msg->token.symbol;
		if ((msg->token.type == msg->coin.type) && is_not_empty_string(msg->coin.uname)) {
			coin_uname = msg->coin.uname;
		} else if (strlen(name) < COIN_UNAME_BUFFSIZE) {
			coin_uname = name;
		} else {
			coin_uname = symbol;
		}
		coin_decimals = (uint8_t) msg->token.decimals;
		coin_type = msg->token.type;
	} else {
		name = "Unkown Message";
	}

	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->total_height = SCREEN_HEIGHT;
	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = name;
	// view->coin_symbol = symbol;
	view->coin_symbol = res_getLabel(LANG_LABEL_SEND);

	double send_value = 0;
	ret = 0;
	if (is_transfer) {
		ret = bignum2double(clause->data.bytes + 36, 32, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	} else if (is_transfer_from) {
		ret = bignum2double(clause->data.bytes + 68, 32, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	} else if (clause->value.size > 0) {
		ret = bignum2double(clause->value.bytes, clause->value.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	} else {
		tmpbuf[0] = 0;
	}
	if (ret != 0) {
		db_error("get send_value false ret:%d", ret);
		tmpbuf[0] = 0;
	}
	db_msg("get send_value:%.18lf str:%s", send_value, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, "VeChain");

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	if (is_transfer_from) {
		tmpbuf[0] = '0';
		tmpbuf[1] = 'x';
		ethereum_address_checksum(clause->data.bytes + 16, tmpbuf + 2, false, 0);
	} else {
		ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
		db_msg("my address ret:%d addr:%s", ret, tmpbuf);
	}
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	tmpbuf[0] = '0';
	tmpbuf[1] = 'x';
	if (is_transfer) {
		ethereum_address_checksum(clause->data.bytes + 16, tmpbuf + 2, false, 0);
	} else if (is_transfer_from) {
		ethereum_address_checksum(clause->data.bytes + 48, tmpbuf + 2, false, 0);
	} else if (clause->to.size > 0) {
		ethereum_address_checksum(clause->to.bytes, tmpbuf + 2, false, 0);
	} else {
		tmpbuf[0] = 0;
	}
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

	view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
	double p = (msg->gas_price > 0) ? (double) msg->gas_price : 1000.0;
	snprintf(tmpbuf, sizeof(tmpbuf), "%.2f", ((double) msg->gas_limit * (1 + (double) ((double) msg->price_coef / 255.0)) / p));
	db_msg("feed value:%s", tmpbuf);
	view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_MAXID, "VTHO");

	if (clause->data.size && !detected_data) {
		view->total_height += SCREEN_HEIGHT;
		view_add_txt(TXS_LABEL_DATA_TITLE, "Data:");
		format_data_to_hex(clause->data.bytes, clause->data.size, tmpbuf, sizeof(tmpbuf));
		view_add_txt(TXS_LABEL_DATA_CONTENT, tmpbuf);
	}

	//save coin info
	if (trans_token && coin_type && view->msg_from == MSG_FROM_QR_APP) {
		if (!storage_isCoinExist(coin_type, coin_uname)) {
			// if (config) {
			// 	storage_save_coin_info(config);
			// } 
			
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