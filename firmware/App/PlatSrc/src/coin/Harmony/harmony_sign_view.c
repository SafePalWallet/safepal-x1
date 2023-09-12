#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Harmony/harmony_sign.c"

#endif

#include "coin_util_hw.h"

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
	HarmonySignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));

	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -102;
	}
	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);
	const CoinConfig *config = getCoinConfig(msg->coin.type, msg->coin.uname);
	if (!config) {
		db_error("invalid request");
		return -103;
	}

	int coin_type = COIN_TYPE_HARMONY;
	const char *coin_uname = config->uname;
	const char *name = config->name;
	const char *symbol = config->symbol;
	uint8_t coin_decimals = config->decimals;

	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->total_height = 2 * SCREEN_HEIGHT;
	view->coin_type = s->req.coin.type;
	view->coin_uname = s->req.coin.uname;
	view->coin_name = name;
	// view->coin_symbol = symbol;
	view->coin_symbol = res_getLabel(LANG_LABEL_SEND);

	double send_value = 0;
	ret = 0;
	if (msg->value.size > 0) {
		ret = bignum2double(msg->value.bytes, msg->value.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	} else {
		tmpbuf[0] = 0;
	}
	if (ret != 0) {
		db_error("get send_value false ret:%d", ret);
		tmpbuf[0] = 0;
	}
	db_error("get send_value:%.18lf str:%s", send_value, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, "Harmony");

	strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
	db_msg("my address ret:%d addr:%s", ret, tmpbuf);
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	if (msg->to.size == 20) {
		harmony_gen_address(tmpbuf, msg->to.bytes);
	} else {
		tmpbuf[0] = 0;
	}
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

	
	view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
	format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->gas_limit * msg->gas_price, 18);
	db_msg("feed value:%s", tmpbuf);
	view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

	if (msg->data.size) {
		view->total_height = 3 * SCREEN_HEIGHT;
		view_add_txt(TXS_LABEL_DATA_TITLE, "Data:");
		format_data_to_hex(msg->data.bytes, msg->data.size, tmpbuf, sizeof(tmpbuf));
		view_add_txt(TXS_LABEL_DATA_CONTENT, tmpbuf);
	}
	if (view->msg_from == MSG_FROM_QR_APP) {
		storage_save_coin(COIN_TYPE_HARMONY, coin_uname);
	}
	return 0;
}

#endif
