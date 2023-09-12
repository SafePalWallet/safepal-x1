#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Polkadot/polkadot_sign.c"

#endif

#include "coin_util_hw.h"

enum {
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_FEED_TILE,
	TXS_LABEL_FEED_VALUE,
	TXS_LABEL_PAYFROM_TITLE,
	TXS_LABEL_PAYFROM_ADDRESS,
	TXS_LABEL_PAYTO_TITLE,
	TXS_LABEL_PAYTO_ADDRESS,
	TXS_LABEL_MAXID,
};

static int show_balance_transfer(const CoinConfig *config, PolkadotSignTxReq *msg, DBTxCoinInfo *db, DynamicViewCtx *view) {
	char tmpbuf[64];
	int ret;
	double send_value = 0;

	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -201;
	}

	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);
	Transfer *transfer = &msg->action.transfer;
	if (is_empty_string(transfer->from)) {
		db_error("invalid from");
		return -202;
	}
	if (is_empty_string(transfer->to)) {
		db_error("invalid to");
		return -203;
	}
	unsigned char *pubkey = (unsigned char *) tmpbuf;
	memset(pubkey, 0, 32);
	ret = polkadot_decode_address(transfer->to, pubkey);
	if (ret < 0) {
		db_error("invalid to");
		return -204;
	}
	if (pubkey[0] != msg->network) {
		db_error("invalid to network");
		return -205;
	}

	memset(pubkey, 0, 32);
	ret = polkadot_decode_address(transfer->from, pubkey);
	if (ret < 0) {
		db_error("invalid from");
		return -206;
	}
	if (pubkey[0] != msg->network) {
		db_error("invalid from network");
		return -207;
	}


	HDNode hdnode;
	memset(&hdnode, 0, sizeof(HDNode));
	ret = wallet_get_hdnode(config->type, config->uname, &hdnode);
	if (ret != 0) {
		return -421;
	}
	db_secure("pubkey:%s", debug_ubin_to_hex(hdnode.public_key, 33));
	if (memcmp(hdnode.public_key + 1, pubkey + 1, 32) != 0) {
		db_error("miss match account");
		return -208;
	}

	ret = bignum2double(transfer->amount.bytes, transfer->amount.size, config->decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	if (ret != 0) {
		db_error("get send_value false ret:%d", ret);
		tmpbuf[0] = 0;
	}
	db_error("get send_value:%.15lf str:%s", send_value, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
    view_add_txt(TXS_LABEL_TOTAL_VALUE, config->symbol);

	// snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);
	// snprintf(tmpbuf, sizeof(tmpbuf), "\xe2\x89\x88%s%.2f", money_symbol, ex_rate * send_value);
	// view_add_txt(TXS_LABEL_TOTAL_MONEY, tmpbuf);
	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, config->name);

	strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));
	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, transfer->from);

	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, transfer->to);

	view_add_txt(TXS_LABEL_FEED_TILE, "Tip:");
	ret = bignum2double(msg->tip.bytes, msg->tip.size, config->decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	if (ret != 0) {
		db_error("gen feed false ret:%d", ret);
		tmpbuf[0] = 0;
	}
	db_msg("feed value:%s", tmpbuf);
	view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, config->symbol);
	return 0;
}

static int on_sign_show(void *session, DynamicViewCtx *view) {
	int ret;
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	PolkadotSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;

	memset(db, 0, sizeof(DBTxCoinInfo));

	int coin_type = 0;
	const char *coin_uname = "";
	const char *name = "";
	const char *symbol = "";

	const CoinConfig *config = getCoinConfig(msg->coin.type, msg->coin.uname);
	if (!config) {
		db_error("not supported type:%d name:%s", msg->coin.type, msg->coin.uname);
		return -113;
	}
	name = config->name;
	symbol = config->symbol;
	coin_type = config->type;
	coin_uname = config->uname;

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
	switch (msg->call_type) {
		case CALL_TYPE_BALANCE_TRANSFER:
			return show_balance_transfer(config, msg, db, view);
			break;
		default:
			db_error("invalid call type:%d", msg->call_type);
			return -118;
	}
}

#endif