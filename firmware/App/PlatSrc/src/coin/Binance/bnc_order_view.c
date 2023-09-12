#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Binance/bnc_order.c"

#endif

enum {
	TXS_LABEL_ORDER_ADDR_VALUE,
	TXS_LABEL_TYPE_TITLE,
	TXS_LABEL_TYPE_VALUE,
	TXS_LABEL_SIDE_TITLE,
	TXS_LABEL_SIDE_VALUE,
	TXS_LABEL_PRICE_TITLE,
	TXS_LABEL_PRICE_VALUE,
	TXS_LABEL_AMOUNT_TITLE,
	TXS_LABEL_AMOUNT_VALUE,
	TXS_LABEL_MAXID,
};

static int on_sign_show(void *session, DynamicViewCtx *view) {
#if 0
	char tmpbuf[128];
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	int ret;
	BncNewOrderRequest *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));

	int coin_type = COIN_TYPE_BNC;
	db->coin_type = coin_type;
	strlcpy(db->coin_uname, "DEX", sizeof(db->coin_uname));
	db->tx_type = TX_TYPE_ORDER;
	bnc_pretty_dex_symbol(db->coin_name, msg->symbol, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, db->coin_name, sizeof(db->coin_symbol));

	view->total_height = SCREEN_HEIGHT;
	view->coin_type = coin_type;
	view->coin_uname = "DEX";
	view->coin_name = ""; //not disable name
	view->coin_symbol = db->coin_symbol;

	memset(tmpbuf, 0, sizeof(tmpbuf));
	ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, "DEX", 0, requestIsTestNet(msg));
	db_msg("my address ret:%d addr:%s", ret, tmpbuf);
	view_add_txt(TXS_LABEL_ORDER_ADDR_VALUE, tmpbuf);

	view_add_txt(TXS_LABEL_TYPE_TITLE, res_getLabel(LANG_LABEL_ORDER_TYPE));
	if (msg->ordertype == 2) {
		view_add_txt(TXS_LABEL_TYPE_VALUE, res_getLabel(LANG_LABEL_LIMIT_ORDER));
	} else {
		view_add_txt(TXS_LABEL_TYPE_VALUE, "Unkonw");
	}

	view_add_txt(TXS_LABEL_SIDE_TITLE, res_getLabel(LANG_LABEL_ORDER_SIDE));
	if (msg->side == 1) {
		HWND h = view_add_txt(TXS_LABEL_SIDE_VALUE, res_getLabel(LANG_LABEL_ORDER_SIDE_BUY));
		setLabelTextColor(h, res_getTextHColor(2));
		db->flag |= 1;
	} else if (msg->side == 2) {
		HWND h = view_add_txt(TXS_LABEL_SIDE_VALUE, res_getLabel(LANG_LABEL_ORDER_SIDE_SELL));
		setLabelTextColor(h, res_getTextHColor(0));
		db->flag |= 2;
	} else {
		view_add_txt(TXS_LABEL_SIDE_VALUE, "Unkonw");
	}

	view_add_txt(TXS_LABEL_PRICE_TITLE, res_getLabel(LANG_LABEL_ORDER_PRICE));

	double price = ((double) msg->price) / 100000000;
	snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", price);
	view_add_txt(TXS_LABEL_PRICE_VALUE, tmpbuf);

	strlcpy(db->currency_value, tmpbuf, sizeof(db->currency_value));

	view_add_txt(TXS_LABEL_AMOUNT_TITLE, res_getLabel(LANG_LABEL_ORDER_AMOUNT));
	double quantity = ((double) msg->quantity) / 100000000;
	snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", quantity);
	pretty_float_string(tmpbuf, 1);
	view_add_txt(TXS_LABEL_AMOUNT_VALUE, tmpbuf);
	strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
	return 0;
	#endif
}

#endif