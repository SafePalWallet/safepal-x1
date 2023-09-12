#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Cardano/cardano_sign.c"

#endif

#include "coin_util_hw.h"

static int check_add_value(int64_t *rs, int64_t v) {
	if (v <= 0) return 0;
	if (LLONG_MAX - *rs < v) {
		return 0;
	} else {
		*rs += v;
		return 1;
	}
}

static int on_sign_show(void *session, DynamicViewCtx *view) {
	char tmpbuf[128] = {0};

	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -101;
	}

	CardanoSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -102;
	}
	const CoinConfig *coinConfig = getCoinConfig(COIN_TYPE_CARDANO, "ADA");
	if (NULL == coinConfig) {
		db_error("not support type:%d name:%s", msg->coin.type, msg->coin.uname);
		return -103;
	}

	const char *name = msg->token.name;
	const char *symbol = msg->token.symbol;
	int coin_type = msg->coin.type;
	const char *coin_uname = msg->coin.uname;
	uint8_t coin_decimals = msg->token.decimals;
	const char *toAdress = NULL;
	const char *changeAdress = NULL;
	uint8_t haveChange = 0;
	db_msg("name:%s symbol:%s coin_uname:%s", name, symbol, coin_uname);

	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = name;
	view->coin_symbol = res_getLabel(LANG_LABEL_SEND);

	int64_t send_main_coin_value = 0;
	int64_t send_token_value = 0;

	int64_t value;
	for (int i = 0; i < msg->output_n; i++) {
		value = msg->outputs[i].value;
		if (is_empty_string(msg->outputs[i].address)) {
			db_error("invalid output no:%d value:%lld", i, value);
			break;
		}

		if (!msg->outputs[i].is_change_address) {
			if (!check_add_value(&send_main_coin_value, value)) {
				db_error("invalid output no:%d value:%lld", i, value);
				break;
			}

			toAdress = msg->outputs[i].address;

			if (msg->operation_type == ADA_TOKEN) {
				if (msg->outputs[i].assets_n != 1) {
					db_error("Only one token can be transferred at a time");
					return -104;
				}

				CardanoAssets assets = msg->outputs[i].assets[0];

				if (!check_add_value(&send_token_value, assets.amount)) {
					db_error("invalid output token");
					break;
				}
			}
		} else {
			haveChange ++;
			changeAdress = msg->outputs[i].address;
		}
	}

	db_msg("send_main_coin_value:%d send_token_value:%d", send_main_coin_value, send_token_value);

	if (msg->operation_type == ADA_TOKEN) {
		format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_token_value, coin_decimals);
		view_add_txt(0, tmpbuf);
		view_add_txt(0, symbol);
	}

	format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_main_coin_value, coinConfig->decimals);
	view_add_txt(0, tmpbuf);
	view_add_txt(0, coinConfig->symbol);

	view_add_txt(0, "Chain:");
	view_add_txt(0, coinConfig->name);

    view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
    view_add_txt(0, toAdress);

    view_add_txt(0, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
	format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->fee, coinConfig->decimals);
	view_add_txt(0, tmpbuf);
	view_add_txt(0, coinConfig->symbol);

    if(haveChange > 0) {
		view_add_txt(0, res_getLabel(LANG_LABEL_TXS_CHANGE_TITLE));
		omit_string(tmpbuf, changeAdress, 26, 11);
		view_add_txt(0, tmpbuf);
	}

	//save coin info
	if (coin_type && view->msg_from == MSG_FROM_QR_APP) {
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
