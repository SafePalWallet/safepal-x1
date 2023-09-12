#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Theta/theta_sign.c"

#endif

#include "coin_util_hw.h"
#include "storage_manager.h"

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
	TXS_LABEL_DATA_TITLE,
	TXS_LABEL_DATA_CONTENT,
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
	ThetaSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
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
	const CoinConfig *config = NULL;

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
	} else {
		db_error("unsupport token");
		return -103;
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
	view->total_height = 2 * SCREEN_HEIGHT;
	ret = 0;
	if (msg->theta_amount.size > 0) {
		ret = bignum2double(msg->theta_amount.bytes, msg->theta_amount.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	} else {
		ret = bignum2double(msg->tfuel_amount.bytes, msg->tfuel_amount.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	}
	if (ret != 0) {
		db_error("get send_value false ret:%d", ret);
		tmpbuf[0] = 0;
	}
	db_msg("get send_value:%.18lf str:%s", send_value, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, "Theta");

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	if (msg->from.size > 0) {
		tmpbuf[0] = '0';
		tmpbuf[1] = 'x';
		ethereum_address_checksum(msg->from.bytes, tmpbuf + 2, false, 0);
	} else {
		ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
		db_msg("my address ret:%d addr:%s", ret, tmpbuf);
	}
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	tmpbuf[0] = '0';
	tmpbuf[1] = 'x';
	if (msg->to.size > 0) {
		tmpbuf[0] = '0';
		tmpbuf[1] = 'x';
		ethereum_address_checksum(msg->to.bytes, tmpbuf + 2, false, 0);
	} else {
		tmpbuf[0] = 0;
	}
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

	strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));
	view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
	bignum2double(msg->fee.bytes, msg->fee.size, 18, NULL, tmpbuf, sizeof(tmpbuf));
	db_msg("feed value:%s", tmpbuf);
	view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_FEED_VALUE, "TFUEL");

	//save coin info
	if (coin_type && view->msg_from == MSG_FROM_QR_APP) {
		if (!storage_isCoinExist(coin_type, coin_uname)) {
			if (config) {
				storage_save_coin_info(config);
			}
		}
	}
	return 0;
}

#endif