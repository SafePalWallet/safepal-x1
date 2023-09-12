#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Bitcoin/bitcoin_sign.c"

#endif

#include "dynamic_win.h"
#include "storage_manager.h"

enum {
	TXS_LABEL_TOTAL_TILE,
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_FEED_TILE,
	TXS_LABEL_FEED_VALUE,
	TXS_LABEL_MAXID,
};

static int on_sign_show(void *session, DynamicViewCtx *view) {
	char tmpbuf[128];
	// if (view->show_more) {
	// 	return on_sign_show_more(session, view);
	// }
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	BitcoinSignRequest *msg = &s->req;
	DBTxCoinInfo *db = &view->db;

	memset(db, 0, sizeof(DBTxCoinInfo));
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -102;
	}
	const CoinConfig *coinConfig = getCoinConfig(COIN_TYPE_BITCOIN, msg->coin.uname);
	if (NULL == coinConfig) {
		db_error("not support type:%d name:%s", msg->coin.type, msg->coin.uname);
		return -181;
	}
	storage_save_coin_info(coinConfig);
	int64_t in_value = 0;
	int64_t out_value = 0;
	int change_item_index = -1;
	int64_t change_value = 0;
	int64_t feed_value = 0;
	int64_t send_value = 0;
	int out_item_count = 0;
	int64_t value;
	int err = 0;
	uint16_t coin_decimals = coinConfig->decimals;
	db_msg("decimals:%d ", coin_decimals);
	do {
		if (msg->input_n <= 0) {
			err = 101;
			db_error("input:0");
			break;
		}
		if (msg->output_n <= 0) {
			err = 102;
			db_error("output:0");
			break;
		}
		for (int i = 0; i < msg->input_n; i++) {
			value = msg->inputs[i].value;
			if (is_empty_string(msg->inputs[i].address) && msg->inputs[i].script.size <= 0) {
				err = 110;
				db_error("invalid input no:%d value:%lld", i, value);
				break;
			}
			if (!check_add_value(&in_value, value)) {
				err = 112;
				db_error("invalid input no:%d value:%lld", i, value);
				break;
			}
			if (msg->inputs[i].txid.size != 32) {
				err = 113;
				db_error("invalid input no:%d txid size:%d", i, msg->inputs[i].txid.size);
				break;
			}
			if (is_empty_string(msg->inputs[i].path)) {
				err = 114;
				db_error("input no:%d empty path", i);
				break;
			}
		}
		if (err) {
			break;
		}
		for (int i = 0; i < msg->output_n; i++) {
			value = msg->outputs[i].value;
			if (is_empty_string(msg->outputs[i].address)) {
				err = 130;
				db_error("invalid input no:%d value:%lld", i, value);
				break;
			}
			if (!check_add_value(&out_value, value)) {
				err = 131;
				db_error("invalid output no:%d value:%lld", i, value);
				break;
			}
			if (msg->outputs[i].flag & BITCOIN_OUTPUT_FLAG_CHANGE) {
				if (change_item_index != -1) {
					err = 132;
					db_error("more change address");
					break;
				}
				if (is_empty_string(msg->outputs[i].path)) {
					err = 133;
					db_error("empty change path");
					break;
				}
				change_item_index = i;
				change_value += value;
			} else {
				out_item_count++;
			}
		}
		if (err) {
			break;
		}
		if (out_value >= in_value) {
			err = 139;
			db_error("out_value:%lld > in_value:%lld", out_value, in_value);
			break;
		}
	} while (0);

	if (err) {
		return err > 0 ? -err : err;
	}

	feed_value = in_value - out_value;
	send_value = in_value - change_value;

	const char *money_symbol = proto_get_money_symbol(&msg->exchange);
	db_msg("in_value:%lld out_value:%lld change_value:%lld feed_value:%lld", in_value, out_value, change_value, feed_value);

	int mScreenHeight = SCREEN_HEIGHT;
	int first_output_offset = SCREEN_HEIGHT;//res_getInt(MK_txs_sign, "first_output_offset", 0);
	int output_item_height = 105;//res_getInt(MK_txs_sign, "output_item_height", 0);
	if (!output_item_height) output_item_height = mScreenHeight;

	int num_perpage = mScreenHeight / output_item_height;

	//move ok to right pos
	int total_height = first_output_offset + mScreenHeight * ((out_item_count + num_perpage - 1) / num_perpage);

	db_msg("first_output_offset:%d output_item_height:%d out_item_count:%d total_height:%d num_perpage:%d",
	       first_output_offset, output_item_height, out_item_count, total_height, num_perpage);

	db->coin_type = COIN_TYPE_BITCOIN;
	strlcpy(db->coin_name, coinConfig->name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, coinConfig->symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coinConfig->uname, sizeof(db->coin_uname));

	view->has_more = 1;
	view->total_height = total_height;
	view->coin_type = COIN_TYPE_BITCOIN;
	view->coin_uname = coinConfig->uname;
	view->coin_name = coinConfig->name;
	// view->coin_symbol = coinConfig->symbol;
	view->coin_symbol = res_getLabel(LANG_LABEL_SEND);;

	// view_add_txt(TXS_LABEL_TOTAL_TILE, res_getLabel(LANG_LABEL_TXS_VALUE_TITLE));

	format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_value, coin_decimals);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_MAXID, coinConfig->symbol);

	int item_index = 0;
	for (int i = 0; i < msg->output_n; i++) {
		if (!(msg->outputs[i].flag & BITCOIN_OUTPUT_FLAG_CHANGE)) {
			if (out_item_count > 1) {
				snprintf(tmpbuf, sizeof(tmpbuf), res_getLabel(LANG_LABEL_TXS_PAYTO_INDEX), item_index + 1);
			} else {
				strlcpy(tmpbuf, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE), sizeof(tmpbuf));
			}
			view_add_txt(TXS_LABEL_MAXID, tmpbuf);
			view_add_txt(TXS_LABEL_MAXID, btc_pretty_address(msg->outputs[i].address, tmpbuf));
			format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->outputs[i].value, coin_decimals);
			view_add_txt(TXS_LABEL_MAXID, tmpbuf);

	        view_add_txt(TXS_LABEL_MAXID, coinConfig->symbol);
			item_index++;
		}
	}

	view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
	format_coin_real_value(tmpbuf, sizeof(tmpbuf), feed_value, coin_decimals);
	view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_MAXID, coinConfig->symbol);

    int change_count = 0;
	for (int i = 0; i < msg->output_n; i++) {
		if (msg->outputs[i].flag & BITCOIN_OUTPUT_FLAG_CHANGE) {
			change_count++;
		}
	}

    item_index = 0;
	if (msg->input_n > 0) {
		for (int i = 0; i < msg->input_n; i++) {
			if (msg->input_n > 1) {
				snprintf(tmpbuf, sizeof(tmpbuf), res_getLabel(LANG_LABEL_TXS_FROM_INDEX), item_index + 1);
			} else {
				strlcpy(tmpbuf, res_getLabel(LANG_LABEL_TXS_FROM_TITLE), sizeof(tmpbuf));
			}
			view_add_txt(TXS_LABEL_MAXID, tmpbuf);
			view_add_txt(TXS_LABEL_MAXID, getInputAddress(coinConfig, &msg->inputs[i], tmpbuf));
			// format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->inputs[i].value, coin_decimals);
			// view_add_txt(TXS_LABEL_MAXID, tmpbuf);

			item_index++;
		}
	}

	if (change_count > 0) {
		for (int i = 0; i < msg->output_n; i++) {
			if (!(msg->outputs[i].flag & BITCOIN_OUTPUT_FLAG_CHANGE)) continue;

			view_add_txt(TXS_LABEL_MAXID, res_getLabel(LANG_LABEL_TXS_CHANGE_TITLE));
			view_add_txt(TXS_LABEL_MAXID, btc_pretty_address(msg->outputs[i].address, tmpbuf));
			// format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->outputs[i].value, coin_decimals);
			// view_add_txt(TXS_LABEL_MAXID, tmpbuf);
		}
	}


	if (view->msg_from == MSG_FROM_QR_APP) {
		int coin_id = coinConfig->id;
		if (is_not_empty_string(msg->coin.path)) {
			int purpose = get_coin_path_purpose(msg->coin.path);
			if (!strcmp(msg->coin.uname, "BTC")) {
				if (purpose == 49) {//BTC2
					coin_id = COIN_ID_BTC2;
				} else if (purpose == 84) {//BTC3
					coin_id = COIN_ID_BTC3;
				}
			} else if (!strcmp(msg->coin.uname, "LTC")) {
				if (purpose == 44) {//LTC2
					coin_id = COIN_ID_LTC2;
				}
			}
		}
		db_msg("coinid:%d uname:%s path:%s", coin_id, msg->coin.uname, msg->coin.path);
		uint64_t account_id = wallet_AccountId();
		if (msg->max_receive_index > 0 && msg->max_receive_index > storage_get_coin_max_index(account_id, coin_id)) {
			storage_set_coin_max_index(account_id, coin_id, msg->max_receive_index);
		}
	}
	return 0;
}

#endif