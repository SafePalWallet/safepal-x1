#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Tron/tron_sign.c"

#endif

#include "coin_util_hw.h"

enum {
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_PAYFROM_TITLE,
	TXS_LABEL_PAYFROM_ADDRESS,
	TXS_LABEL_PAYTO_TITLE,
	TXS_LABEL_PAYTO_ADDRESS,
	TXS_LABEL_APP_MSG_VALUE,
	TXS_LABEL_FIELD_TITLE,
	TXS_LABEL_FIELD_VALUE,
	TXS_LABEL_FIELD_VALUE2,
	TXS_LABEL_VOTE_ADDRESS,
	TXS_LABEL_VOTE_NUMBER,
	TXS_LABEL_MEMO_TITLE,
	TXS_LABEL_MEMO_CONTENT,
	TXS_LABEL_MAXID,
};

static int on_sign_show_transfer_x_contract(int contract_type, coin_state *s, DynamicViewCtx *view) {
	db_msg("on_sign_show_transfer_x_contract");
	char tmpbuf[128];
	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;
	Transaction *transaction = &msg->transaction;
	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);

	int ret;
	int coin_type = msg->coin.type;
	const char *coin_uname = msg->coin.uname;

	const char *name;
	const char *symbol;
	int coin_decimals;

	switch (coin_type) {
		case COIN_TYPE_TRX:
		case COIN_TYPE_TRC10:
		case COIN_TYPE_TRC20:
			break;
		default:
			db_error("invalid coin type:%d", coin_type);
			return -111;
	}
	if (is_empty_string(coin_uname)) {
		db_error("invalid coin:%d uname:%s", coin_type, coin_uname);
		return -112;
	}
	if (transaction->timestamp < 0) {
		db_error("invalid timestamp:%lld", transaction->timestamp);
		return -114;
	}

	const CoinConfig *config = getCoinConfig(coin_type, coin_uname);
	if (config) {
		name = config->name;
		symbol = config->symbol;
		coin_decimals = config->decimals;
	} else {
		name = msg->token.name;
		symbol = msg->token.symbol;
		coin_decimals = msg->token.decimals;
	}

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

	double send_value = 0;
	if (transaction->transfer.big_amount.size > 0) {
		ret = bignum2double(transaction->transfer.big_amount.bytes, transaction->transfer.big_amount.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
	} else {
		int64_t send_amount = transaction->transfer.amount;
		send_value = proto_coin_real_value(send_amount, coin_decimals);
		format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_amount, coin_decimals);
		db_msg("get send_amount:%lld str:%s", send_amount, tmpbuf);
	}
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, "Tron");
	// strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
	// snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);
	// snprintf(tmpbuf, sizeof(tmpbuf), "\xe2\x89\x88%s%.2f", money_symbol, ex_rate * send_value);
	// view_add_txt(TXS_LABEL_TOTAL_MONEY, tmpbuf);
	// strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	memset(tmpbuf, 0, sizeof(tmpbuf));
	ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
	db_msg("my address ret:%d addr:%s", ret, tmpbuf);
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, transaction->transfer.owner_address);
	if (strcmp(tmpbuf, transaction->transfer.owner_address) != 0) {
		db_error("invalid owner_address:%s", transaction->transfer.owner_address);
		return -115;
	}
	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, transaction->transfer.to_address);
	if (tron_decode_address(transaction->transfer.to_address, (unsigned char *) tmpbuf) <= 0) {
		db_error("invalid to_address:%s", transaction->transfer.to_address);
		return -116;
	}
	
	if (!is_empty_string(transaction->memo)) {
		if (is_printable_str(transaction->memo)) {
			view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
			view_add_txt(TXS_LABEL_MEMO_CONTENT, transaction->memo);
		} else {
			view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_HEX_TITLE));
			ret = strlen(transaction->memo);
			if (ret * 2 < (int) sizeof(tmpbuf)) {
				bin_to_hex((const unsigned char *) transaction->memo, ret, tmpbuf);
				view_add_txt(TXS_LABEL_MEMO_CONTENT, tmpbuf);
			} else {
				char *hex = (char *) malloc((ret + 1) * 2);
				if (hex) {
					memset(hex, 0, (ret + 1) * 2);
					bin_to_hex((const unsigned char *) transaction->memo, ret, hex);
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

static int on_sign_show_smart_contract(int contract_type, coin_state *s, DynamicViewCtx *view) {
	db_msg("on_sign_show_smart_contract");
	char tmpbuf[256];
	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;
	const TriggerSmartContract *contract = &msg->transaction.smart_contract;
	int coin_type = msg->coin.type ? msg->coin.type : COIN_TYPE_TRX;
	const char *coin_uname;
	const char *name;
	const char *symbol = msg->contract.name;//show
	coin_uname = "Dapp";
	name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);

	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->total_height = SCREEN_HEIGHT;
	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = name;
	// view->coin_symbol = symbol;
	view->coin_symbol = res_getLabel(LANG_LABEL_SIGN_TRANSACTION);

	view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
	view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, "Tron");

	view_add_txt(TXS_LABEL_APP_MSG_VALUE, "Data:");
	view->flag |= 0x1;
	db->tx_type = TX_TYPE_APP_SIGN_MSG;
	format_data_to_hex(contract->data.bytes, contract->data.size, tmpbuf, 200);
	view_add_txt(TXS_LABEL_APP_MSG_VALUE, tmpbuf);
	return 0;
}

static int on_sign_show_freeze_balance(int contract_type, coin_state *s, DynamicViewCtx *view) {
	char tmpbuf[128];
	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;

	const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
	db->coin_type = COIN_TYPE_TRX;
	const char *name = "FreezeBalance";
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, config->symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

	view->total_height = SCREEN_HEIGHT * 2;
	view->coin_type = COIN_TYPE_TRX;
	view->coin_uname = config->uname;
	view->coin_name = name;
	view->coin_symbol = config->symbol;
	db->tx_type = TX_TYPE_SIGN_MSG;
	const FreezeBalanceContract *contract = &msg->transaction.freeze_balance_contract;
	format_coin_real_value(tmpbuf, sizeof(tmpbuf), contract->frozen_balance, config->decimals);

	view_add_txt(TXS_LABEL_FIELD_TITLE, "Amount Frozen:");
	view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

	if (contract->frozen_duration > 1) {
		snprintf(tmpbuf, sizeof(tmpbuf), "%llu Days", contract->frozen_duration);
	} else {
		snprintf(tmpbuf, sizeof(tmpbuf), "%llu Day", contract->frozen_duration);
	}
	view_add_txt_off(TXS_LABEL_FIELD_TITLE, "Days Frozen:", 55);
	view_add_txt_off(TXS_LABEL_FIELD_VALUE, tmpbuf, 55);

	snprintf(tmpbuf, sizeof(tmpbuf), "%s", resource_code_to_String(contract->resource));
	view_add_txt_off(TXS_LABEL_FIELD_TITLE, "Resources Received:", 55 * 2);
	view_add_txt_off(TXS_LABEL_FIELD_VALUE2, tmpbuf, 55 * 2);

	view_add_txt(TXS_LABEL_PAYTO_TITLE, "Receiving Address:");
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, is_not_empty_string(contract->receiver_address) ? contract->receiver_address : contract->owner_address);
	return 0;
}

static int on_sign_show_unfreeze_balance(int contract_type, coin_state *s, DynamicViewCtx *view) {
	char tmpbuf[128];
	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;

	const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
	db->coin_type = COIN_TYPE_TRX;
	const char *name = "UnfreezeBalance";
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, config->symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

	view->total_height = SCREEN_HEIGHT;
	view->coin_type = COIN_TYPE_TRX;
	view->coin_uname = config->uname;
	view->coin_name = name;
	view->coin_symbol = config->symbol;
	db->tx_type = TX_TYPE_SIGN_MSG;
	const UnFreezeBalanceContract *c = &msg->transaction.un_freeze_balance_contract;

	snprintf(tmpbuf, sizeof(tmpbuf), "%s", resource_code_to_String(c->resource));
	view_add_txt(TXS_LABEL_FIELD_TITLE, "Resources:");
	view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

	view_add_txt_off(TXS_LABEL_FIELD_TITLE, "Recycling Address:", 55);
	view_add_txt_off(TXS_LABEL_FIELD_VALUE2, is_not_empty_string(c->receiver_address) ? c->receiver_address : c->owner_address, 55);
	return 0;
}

static int on_sign_show_vote_witness(int contract_type, coin_state *s, DynamicViewCtx *view) {
	char tmpbuf[128];
	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;
	const VoteWitnessContract *c = &msg->transaction.vote_witness_contract;
	const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
	db->coin_type = COIN_TYPE_TRX;
	const char *name = "VoteWitness";
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, config->symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

	int toal_n = c->vote_n;
	view->total_height = SCREEN_HEIGHT * (toal_n / 3 + 1);
	view->coin_type = COIN_TYPE_TRX;
	view->coin_uname = config->uname;
	view->coin_name = name;
	view->coin_symbol = config->symbol;
	db->tx_type = TX_TYPE_SIGN_MSG;
	int offset = 0;
	for (int i = 0; i < toal_n; i++) {
		Vote *v = c->votes + i;
		offset = SCREEN_HEIGHT * ((i + 1) / 3) + ((i + 1) % 3) * 75;
		view_add_txt_off(TXS_LABEL_VOTE_ADDRESS, v->vote_address, offset);
		snprintf(tmpbuf, sizeof(tmpbuf), "%llu", v->vote_count);
		view_add_txt_off(TXS_LABEL_VOTE_NUMBER, tmpbuf, offset);
	}
	return 0;
}

static int on_sign_show_freeze_balance_v2(int contract_type, coin_state *s, DynamicViewCtx *view) {
    char tmpbuf[64], balance[32];
    DBTxCoinInfo *db = &view->db;
    SignRequest *msg = &s->req;

    const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
    db->coin_type = COIN_TYPE_TRX;
    const char *symbol = "Stake";
    strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

    view->total_height = SCREEN_HEIGHT;
    view->coin_type = COIN_TYPE_TRX;
    view->coin_uname = config->uname;
    view->coin_name = config->name;
    view->coin_symbol = symbol;
    db->tx_type = TX_TYPE_SIGN_MSG;
    const FreezeBalanceV2Contract *contract = &msg->transaction.freeze_balance_v2_contract;

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Amount:");
    format_coin_real_value(balance, sizeof(balance), contract->frozen_balance, config->decimals);
    snprintf(tmpbuf, sizeof(tmpbuf), "%s TRX", balance);
    view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Chain:");
    view_add_txt(TXS_LABEL_FIELD_VALUE, config->name);
    return 0;
}

static int on_sign_show_un_freeze_balance_v2(int contract_type, coin_state *s, DynamicViewCtx *view) {
    char tmpbuf[64], balance[32];
    DBTxCoinInfo *db = &view->db;
    SignRequest *msg = &s->req;

    const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
    db->coin_type = COIN_TYPE_TRX;
    const char *symbol = "Unstake";
    strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

    view->total_height = SCREEN_HEIGHT;
    view->coin_type = COIN_TYPE_TRX;
    view->coin_uname = config->uname;
    view->coin_name = config->name;
    view->coin_symbol = symbol;
    db->tx_type = TX_TYPE_SIGN_MSG;
    const UnfreezeBalanceV2Contract *c = &msg->transaction.un_freeze_balance_v2_contract;

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Amount:");
    format_coin_real_value(balance, sizeof(balance), c->unfreeze_balance, config->decimals);
    snprintf(tmpbuf, sizeof(tmpbuf), "%s TRX", balance);
    view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Chain:");
    view_add_txt(TXS_LABEL_FIELD_VALUE, config->name);
    return 0;
}

static int on_sign_show_withdraw_expire_un_freeze(int contract_type, coin_state *s, DynamicViewCtx *view) {
    char tmpbuf[64], balance[32];
    SignRequest *msg = &s->req;
    DBTxCoinInfo *db = &view->db;

    const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
    db->coin_type = COIN_TYPE_TRX;
    const char *symbol = "Withdraw";
    strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

    view->total_height = SCREEN_HEIGHT;
    view->coin_type = COIN_TYPE_TRX;
    view->coin_uname = config->uname;
    view->coin_name = config->name;
    view->coin_symbol = symbol;
    db->tx_type = TX_TYPE_SIGN_MSG;

    int coin_type = msg->coin.type;
    const char *coin_uname = msg->coin.uname;
    const WithdrawExpireUnfreezeContract *contract = &msg->transaction.withdraw_expire_un_freeze_contract;

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Amount:");
    format_coin_real_value(balance, sizeof(balance), contract->balance, config->decimals);
    snprintf(tmpbuf, sizeof(tmpbuf), "%s TRX", balance);
    view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Chain:");
    view_add_txt(TXS_LABEL_FIELD_VALUE, config->name);
    return 0;
}

static int on_sign_show_delegate_resource_contract(int contract_type, coin_state *s, DynamicViewCtx *view) {
    char tmpbuf[64], balance[32];
    DBTxCoinInfo *db = &view->db;
    SignRequest *msg = &s->req;

    const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
    db->coin_type = COIN_TYPE_TRX;
    const char *symbol = "Delegate";
    strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

    view->total_height = SCREEN_HEIGHT;
    view->coin_type = COIN_TYPE_TRX;
    view->coin_uname = config->uname;
    view->coin_name = config->name;
    view->coin_symbol = symbol;
    db->tx_type = TX_TYPE_SIGN_MSG;
    const DelegateResourceContract *contract = &msg->transaction.delegate_resource_contract;

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Amount:");
    format_coin_real_value(balance, sizeof(balance), contract->balance, config->decimals);
    snprintf(tmpbuf, sizeof(tmpbuf), "%s TRX", balance);
    view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Chain:");
    view_add_txt(TXS_LABEL_FIELD_VALUE, config->name);

    view_add_txt(TXS_LABEL_FIELD_TITLE, "to:");
    view_add_txt(TXS_LABEL_PAYTO_ADDRESS, is_not_empty_string(contract->receiver_address) ? contract->receiver_address : contract->owner_address);
    return 0;
}

static int on_sign_show_un_delegate_resource_contract(int contract_type, coin_state *s, DynamicViewCtx *view) {
    char tmpbuf[64], balance[32];
    DBTxCoinInfo *db = &view->db;
    SignRequest *msg = &s->req;

    const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
    db->coin_type = COIN_TYPE_TRX;
    const char *symbol = "Reclaim";
    strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

    view->total_height = SCREEN_HEIGHT;
    view->coin_type = COIN_TYPE_TRX;
    view->coin_uname = config->uname;
    view->coin_name = config->name;
    view->coin_symbol = symbol;
    db->tx_type = TX_TYPE_SIGN_MSG;
    const UnDelegateResourceContract *contract = &msg->transaction.un_delegate_resource_contract;

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Amount:");
    format_coin_real_value(balance, sizeof(balance), contract->balance, config->decimals);
    snprintf(tmpbuf, sizeof(tmpbuf), "%s TRX", balance);
    view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Chain:");
    view_add_txt(TXS_LABEL_FIELD_VALUE, config->name);
    return 0;
}

static int on_sign_show_cancel_all_un_freeze_v2_contract(int contract_type, coin_state *s, DynamicViewCtx *view) {
    char tmpbuf[64], balance[32];
    DBTxCoinInfo *db = &view->db;
    SignRequest *msg = &s->req;

    const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
    db->coin_type = COIN_TYPE_TRX;
    const char *symbol = "Cancel Unstake";
    strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

    view->total_height = SCREEN_HEIGHT;
    view->coin_type = COIN_TYPE_TRX;
    view->coin_uname = config->uname;
    view->coin_name = config->name;
    view->coin_symbol = symbol;
    db->tx_type = TX_TYPE_SIGN_MSG;

    const CancelAllUnfreezeV2Contract *contract = &msg->transaction.cancel_all_un_freeze_v2_contract;

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Amount:");
    format_coin_real_value(balance, sizeof(balance), contract->balance, config->decimals);
    snprintf(tmpbuf, sizeof(tmpbuf), "%s TRX", balance);
    view_add_txt(TXS_LABEL_FIELD_VALUE, tmpbuf);

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Chain:");
    view_add_txt(TXS_LABEL_FIELD_VALUE, config->name);
    return 0;
}

static int on_sign_show_withdrw_balance_contract(int contract_type, coin_state *s, DynamicViewCtx *view) {
    char tmpbuf[64], balance[32];
    DBTxCoinInfo *db = &view->db;
    SignRequest *msg = &s->req;

    const CoinConfig *config = getCoinConfig(COIN_TYPE_TRX, "TRX");
    db->coin_type = COIN_TYPE_TRX;
    const char *symbol = "Withdraw";
    strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

    view->total_height = SCREEN_HEIGHT;
    view->coin_type = COIN_TYPE_TRX;
    view->coin_uname = config->uname;
    view->coin_name = config->name;
    view->coin_symbol = symbol;
    db->tx_type = TX_TYPE_SIGN_MSG;

    view_add_txt(TXS_LABEL_FIELD_TITLE, "Chain:");
    view_add_txt(TXS_LABEL_FIELD_VALUE, config->name);
    return 0;
}

static int on_sign_show(void *session, DynamicViewCtx *view) {
    coin_state *s = (coin_state *) session;
    if (!s) {
        db_error("invalid session");
        return -1;
    }
    DBTxCoinInfo *db = &view->db;
    SignRequest *msg = &s->req;
    memset(db, 0, sizeof(DBTxCoinInfo));
    switch (msg->transaction.contract_type) {
        case CONTRACT_TYPE_TRANSFER_CONTRACT:
        case CONTRACT_TYPE_TRANSFER_ASSET_CONTRACT:
        case CONTRACT_TYPE_TRANSFER_TRC20_CONTRACT:
            return on_sign_show_transfer_x_contract(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_TRIGGER_SMART_CONTRACT:
            return on_sign_show_smart_contract(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_FREEZE_BALANCE_CONTRACT:
            return on_sign_show_freeze_balance(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_UN_FREEZE_BALANCE_CONTRACT:
            return on_sign_show_unfreeze_balance(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_VOTE_WITNESS_CONTRACT:
            return on_sign_show_vote_witness(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_FREEZE_BALANCE_V2_CONTRACT:
            return on_sign_show_freeze_balance_v2(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_UN_FREEZE_BALANCE_V2_CONTRACT:
            return on_sign_show_un_freeze_balance_v2(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_WITHDRAW_EXPIRE_UN_FREEZE_CONTRACT:
            return on_sign_show_withdraw_expire_un_freeze(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_DELEGATE_RESOURCE_CONTRACT:
            return on_sign_show_delegate_resource_contract(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_UN_DELEGATE_RESOURCE_CONTRACT:
            return on_sign_show_un_delegate_resource_contract(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_CANCEL_All_UN_FREEZE_V2_CONTRACT:
            return on_sign_show_cancel_all_un_freeze_v2_contract(msg->transaction.contract_type, s, view);
        case CONTRACT_TYPE_WITHDRAW_BALANCE_CONTRACT:
            return on_sign_show_withdrw_balance_contract(msg->transaction.contract_type, s, view);
        default:
            return -190;
    }
}

#endif