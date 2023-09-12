#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Stellar/xlm_sign.c"

#endif

#include "storage_manager.h"
#include "dynamic_win.h"

enum {
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_PAYFROM_TITLE,
	TXS_LABEL_PAYFROM_ADDRESS,
	TXS_LABEL_PAYTO_TITLE,
	TXS_LABEL_PAYTO_ADDRESS,
	TXS_LABEL_MEMO_TITLE,
	TXS_LABEL_MEMO_CONTENT,
	TXS_LABEL_ASSET_CODE_TITLE,
	TXS_LABEL_ASSET_CODE_VALUE,
	TXS_LABEL_ASSET_ISSUER_TITLE,
	TXS_LABEL_ASSET_ISSUER_VALUE,
	TXS_LABEL_MAXID,
};

static int show_payment(XlmSignTxReq *msg, DBTxCoinInfo *db, DynamicViewCtx *view, const char *chainName, const char *symbol) {
	char tmpbuf[128];
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -1201;
	}

	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);
	double send_value;
	const char *destination;
	if (msg->op_type == OP_TYPE_PAYMENT) {
		const Payment *tx = &msg->action.payment;
		send_value = ((double) tx->amount) / 10000000;
		destination = tx->destination;
	} else if (msg->op_type == OP_TYPE_CREATE_ACCOUNT) {
		const CreateAccount *tx = &msg->action.createAccount;
		send_value = ((double) tx->starting_balance) / 10000000;
		destination = tx->destination;
	} else {
		return -1;
	}

	db_msg("get send_value:%.7lf str:%s", send_value, tmpbuf);
	snprintf(tmpbuf, sizeof(tmpbuf), "%.7lf", send_value);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
	snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);

	view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

	view_add_txt(TXS_LABEL_ASSET_CODE_TITLE, "Chain:");
	view_add_txt(TXS_LABEL_ASSET_CODE_VALUE, chainName);

	strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, msg->account);

	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, destination);

	if (!is_empty_string(msg->memo)) {
		int memolen = strlen(msg->memo);
		if (is_printable_str(msg->memo)) {
			view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
			view_add_txt(TXS_LABEL_MEMO_CONTENT, msg->memo);
		} else {
			view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_HEX_TITLE));
			if (memolen * 2 < (int) sizeof(tmpbuf)) {
				bin_to_hex((const unsigned char *) msg->memo, memolen, tmpbuf);
				view_add_txt(TXS_LABEL_MEMO_CONTENT, tmpbuf);
			} else {
				db_error("invalid memo len:%d", memolen);
				return -1202;
			}
		}
	} else {
		// view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
		// view_add_txt(TXS_LABEL_MEMO_CONTENT, "");
	}
	view->total_height = 2 * SCREEN_HEIGHT;
	return 0;
}

static int show_changeTrust(XlmSignTxReq *msg, DBTxCoinInfo *db, DynamicViewCtx *view) {
	char buff[40];
	ChangeTrust *tx = &msg->action.changeTrust;
	const char *chain_name = "Stellar";
	// view->coin_symbol = chain_name;
	strlcpy(db->coin_name, chain_name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, chain_name, sizeof(db->coin_symbol));

	if (tx->action == 0) {
		// view->coin_name = res_getLabel(LANG_LABEL_XLM_DISTRUST_ASSET);
		view->coin_symbol = res_getLabel(LANG_LABEL_XLM_DISTRUST_ASSET);
		snprintf(buff, sizeof(buff), "- %s", tx->asset_code);
	} else {
		// view->coin_name = res_getLabel(LANG_LABEL_XLM_TRUST_ASSET);
		view->coin_symbol = res_getLabel(LANG_LABEL_XLM_TRUST_ASSET);
		snprintf(buff, sizeof(buff), "+ %s", tx->asset_code);
	}
	strlcpy(db->send_value, buff, sizeof(db->send_value));

	view_add_txt(TXS_LABEL_ASSET_CODE_TITLE, res_getLabel(LANG_LABEL_XLM_ASSET_CODE));
	view_add_txt(TXS_LABEL_ASSET_CODE_VALUE, tx->asset_code);
	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, chain_name);
	view_add_txt(TXS_LABEL_ASSET_ISSUER_TITLE, res_getLabel(LANG_LABEL_XLM_ASSET_ISSUER));
	view_add_txt(TXS_LABEL_ASSET_ISSUER_VALUE, tx->asset_issuer);
	return 0;
}
static int on_sign_show(void *session, DynamicViewCtx *view) {
	int ret;
	unsigned char pubkey[32] = {0};
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	XlmSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));
	if (xlm_decode_address(msg->account, (unsigned char *) pubkey) < 1) {
		db_error("invalid account");
		return -201;
	}

	HDNode hdnode;
	memset(&hdnode, 0, sizeof(HDNode));
	ret = wallet_get_hdnode(COIN_TYPE_XLM, UNAME_XLM, &hdnode);
	if (ret != 0) {
		return -401;
	}
	db_secure("pubkey:%s", debug_ubin_to_hex(hdnode.public_key, 33));
	if (memcmp(hdnode.public_key + 1, pubkey, 32) != 0) {
		db_error("miss match account");
		return -202;
	}
	const CoinConfig *config = getCoinConfig(COIN_TYPE_XLM, msg->coin.uname);
	if (!config) {
		config = getCoinConfig(COIN_TYPE_XLM, UNAME_XLM);
	}
	int coin_type = COIN_TYPE_XLM;
	const char *coin_uname = msg->coin.uname;
	const char *name = config->name;
	const char *symbol = config->symbol;

	if (msg->op_type == OP_TYPE_PAYMENT) {
		const Payment *action = &msg->action.payment;
		if (!xlm_asset_is_XLM(action->asset_code, action->asset_issuer)) {
			name = action->asset_code;
			symbol = action->asset_code;
		}
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

	ret = -405;
	if (msg->op_type == OP_TYPE_PAYMENT || msg->op_type == OP_TYPE_CREATE_ACCOUNT) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
		ret = show_payment(msg, db, view, config->name,symbol);
	} else if (msg->op_type == OP_TYPE_CHANGETRUST) {
		ret = show_changeTrust(msg, db, view);
	}
	if (ret != 0) {
		db_error("show tx false ret:%d", ret);
		return ret;
	}

	//save coin info
	if (view->msg_from == MSG_FROM_QR_APP && msg->op_type == OP_TYPE_PAYMENT) {
		if (!storage_isCoinExist(coin_type, coin_uname)) {
			DBCoinInfo dbinfo;
			memset(&dbinfo, 0, sizeof(dbinfo));
			dbinfo.type = (uint8_t) coin_type;
			dbinfo.curv = coin_get_curv_id(coin_type, coin_uname);
			dbinfo.decimals = 7;
			strncpy(dbinfo.uname, coin_uname, COIN_UNAME_MAX_LEN);
			strncpy(dbinfo.name, name, COIN_NAME_MAX_LEN);
			strncpy(dbinfo.symbol, symbol, COIN_SYMBOL_MAX_LEN);
			storage_save_coin_dbinfo(&dbinfo);
		}
	}
	return 0;
}

#endif
