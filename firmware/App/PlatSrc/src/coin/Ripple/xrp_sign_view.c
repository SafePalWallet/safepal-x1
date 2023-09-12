#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Ripple/xrp_sign.c"

#endif

#include "coin_util_hw.h"

enum {
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_FEED_TILE,
	TXS_LABEL_FEED_VALUE,
	TXS_LABEL_TAG_CONTENT,
	TXS_LABEL_PAYFROM_TITLE,
	TXS_LABEL_PAYFROM_ADDRESS,
	TXS_LABEL_PAYTO_TITLE,
	TXS_LABEL_PAYTO_ADDRESS,
	TXS_LABEL_ACCOUNTSET_TITLE,
	TXS_LABEL_ACCOUNTSET_VALUE,
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
	XrpSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));

	const CoinConfig *config = getCoinConfig(msg->coin.type, msg->coin.uname);
	if (!config) {
		db_error("get coin config false");
		return -201;
	}
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -1;
	}

	int coin_type = COIN_TYPE_XRP;
	const char *coin_uname = config->uname;
	const char *name = config->name;
	const char *symbol = config->symbol;

	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->total_height = SCREEN_HEIGHT;
	view->coin_type = s->req.coin.type;
	view->coin_uname = s->req.coin.uname;
	view->coin_name = name;
	// view->coin_symbol = symbol;

	if (msg->tx_type == 0) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
		double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
		const char *money_symbol = proto_get_money_symbol(&msg->exchange);
		double send_value = ((double) msg->amount) / 1000000;
		db_msg("get send_value:%.8lf str:%s", send_value, tmpbuf);
		snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", send_value);
		view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	    view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

		view_add_txt(TXS_LABEL_MAXID, "Chain:");
		view_add_txt(TXS_LABEL_MAXID, "Ripple");
	
		view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
		db_msg("my address ret:%d addr:%s", ret, tmpbuf);
		view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

		view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		view_add_txt(TXS_LABEL_PAYTO_ADDRESS, msg->destination);

		view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
		snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", ((double) msg->fee) / 1000000);
		view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

		const char *tag = "Tag:";
		if (msg->destination_tag > 0) {
			snprintf(tmpbuf, sizeof(tmpbuf), "%s %u", tag, msg->destination_tag);
			view_add_txt(TXS_LABEL_TAG_CONTENT, tmpbuf);
		} else {
			// snprintf(tmpbuf, sizeof(tmpbuf), "%s ---", tag);
		}
		// view_add_txt(TXS_LABEL_TAG_CONTENT, tmpbuf);
		
	} else if (msg->tx_type == 3) {
		if (msg->accountSet.MessageKey.size > 0) {
			if (msg->accountSet.MessageKey.size > 0xFF) {
				db_error("invalid MessageKey size:%d", msg->accountSet.MessageKey.size);
				return -1;
			}
			db->tx_type = TX_TYPE_SIGN_MSG;
			view->coin_symbol = "Sign Message";

			view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
			view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

			view_add_txt(TXS_LABEL_MAXID, "Chain:");
			view_add_txt(TXS_LABEL_MAXID, "Ripple");
			
			snprintf(db->send_value, sizeof(db->send_value), "%s", "Set MessageKey");
			view_add_txt(TXS_LABEL_ACCOUNTSET_TITLE, "Set MessageKey:");
			format_data_to_hex_b(msg->accountSet.MessageKey.bytes, msg->accountSet.MessageKey.size, tmpbuf, sizeof(tmpbuf));
			view_add_txt(TXS_LABEL_ACCOUNTSET_VALUE, tmpbuf);
		}
	} else {
		db_error("invalid tx_type:%d", msg->tx_type);
		return -1;
	}

	//save coin info
	if (view->msg_from == MSG_FROM_QR_APP) {
		storage_save_coin_info(config);
	}
	return 0;
}

#endif