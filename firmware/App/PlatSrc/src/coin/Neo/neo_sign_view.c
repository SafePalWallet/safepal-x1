#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Neo/neo_sign.c"

#endif

enum {
	TXS_LABEL_CLAIN_TITLE,
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_FEED_TILE,
	TXS_LABEL_FEED_VALUE,
	TXS_LABEL_PAYFROM_TITLE,
	TXS_LABEL_PAYFROM_ADDRESS,
	TXS_LABEL_PAYTO_TITLE,
	TXS_LABEL_PAYTO_ADDRESS,

	TXS_LABEL_UTX_TOTAL_TILE,
	TXS_LABEL_UTX_TOTAL_VALUE,
	TXS_LABEL_UTX_TOTAL_MONEY,
	TXS_LABEL_UTX_FEED_TILE,
	TXS_LABEL_UTX_FEED_VALUE,

	TXS_LABEL_MAXID,
};

//BEP5 token
static int show_invocation_tx(coin_state *s, DynamicViewCtx *view, struct pbc_rmessage *rmsg) {
	TokenTrans ts;
	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;
	int ret = init_check_TokenTran(s, rmsg, &ts);
	if (ret) {
		db_error("check_TokenTran false ret:%d", ret);
		return ret;
	}
	db_msg("from:%s to:%s value:%lld", ts.from, ts.to, ts.value);
	char buff[128];
	if (neo_decode_address(ts.to, (unsigned char *) buff) < 0) {
		db_error("decode address:%s false", ts.to);
		return -111;
	}
	if (ts.system_fee < 0) {
		db_error("decode invalid system fee:%lld", ts.system_fee);
		return -112;
	}
	InOutPuts inouts[1];
	InOutPutSum sumi;
	InOutPutSum sumo;
	int64_t fee = 0;
	int code = -1;
	neo_rmsg_InOutPuts(rmsg, inouts);
	do {
		ret = gen_inout_summary(s, inouts, &sumi, &sumo, 1 | 4);
		if (ret != 0) {
			db_error("summary input false ret:%d", ret);
			code = -115;
			break;
		}
		if (sumi.neo_n || sumo.neo_n) {
			db_error("invalid inout put,have NEO");
			code = -116;
			break;
		}
		fee = sumi.gas_values - sumo.gas_values;
		if (fee < 0) {
			db_error("invalid fee:%lld in:%lld out:%lld", fee, sumi.gas_values, sumo.gas_values);
			code = -117;
			break;
		}
		code = 0;
	} while (0);
	neo_free_InOutPuts(inouts);
	if (code) {
		return code;
	}
	fee += ts.system_fee;

	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);

	int coin_type = msg->coin.type;
	const char *coin_uname = msg->coin.uname;
	const char *name = ts.token.name;
	const char *symbol = ts.token.symbol;
	int coin_decimals = ts.token.decimals;

	int64_t send_amount = ts.value;
	double send_value = proto_coin_real_value(send_amount, coin_decimals);

	// tx_set_db_view_info(db, view, coin_type, coin_uname, name, symbol);
	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = name;
	view->coin_symbol = res_getLabel(LANG_LABEL_SEND);

	format_coin_real_value(buff, sizeof(buff), send_amount, coin_decimals);
	db_msg("get send_amount:%lld str:%s", send_amount, buff);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, buff);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);


	strlcpy(db->send_value, buff, sizeof(db->send_value));
	snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);
	strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

	view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
	view_add_txt(TXS_LABEL_PAYTO_ADDRESS, ts.to);

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, s->myaddr);

	view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
	snprintf(buff, sizeof(buff), "%.8lf", ((double) fee) / 100000000);
	pretty_float_string(buff, 1);
	view_add_txt(TXS_LABEL_FEED_VALUE, buff);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, "GAS");

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

static int show_claim_tx(coin_state *s, DynamicViewCtx *view, InOutPuts *inouts) {
	char buff[128];
	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;
	InOutPutSum sumi;
	InOutPutSum sumo;

	if (gen_inout_summary(s, inouts, &sumi, &sumo, 1 | 2) != 0) {
		db_error("gen claim sum false");
		return -211;
	}
	if (sumo.gas_n != 1 || !sumo.gas_values) {
		db_error("invalid output gas n:%d value:%lld", sumo.gas_n, sumo.gas_values);
		return -212;
	}
	if (sumi.gas_values > sumo.gas_values) {
		db_error("invalid input gas_values:%lld > out gas_values:%lld", sumi.gas_values, sumo.gas_values);
		return -213;
	}
	if (sumi.neo_n) {
		db_error("invalid input neo n:%d", sumi.neo_n);
		return -214;
	}
	db_msg("output gas n:%d value:%lld", sumo.gas_n, sumo.gas_values);

	const CoinConfig *config = getCoinConfig(COIN_TYPE_NEO, "GAS");
	if (!config) {
		db_error("coin config error");
		return -501;
	}

	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);

	int64_t send_amount = sumo.gas_values;
	double send_value = proto_coin_real_value(send_amount, config->decimals);

	tx_set_db_view(config, db, view);
	view->total_height = SCREEN_HEIGHT;

	view_add_txt(TXS_LABEL_CLAIN_TITLE, res_getLabel(LANG_LABEL_CLAIM_GAS_TITLE));
	format_coin_real_value(buff, sizeof(buff), send_amount, config->decimals);
	db_msg("get send_amount:%lld str:%s", send_amount, buff);
	view_add_txt_off(TXS_LABEL_TOTAL_VALUE, buff, 40);
	strlcpy(db->send_value, buff, sizeof(db->send_value));
	snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);

	snprintf(buff, sizeof(buff), "\xe2\x89\x88%s%.2f", money_symbol, ex_rate * send_value);
	view_add_txt_off(TXS_LABEL_TOTAL_MONEY, buff, 45);
	strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));
	storage_save_coin_info(config);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, "GAS");
	return 0;
}

static int show_contract_tx(coin_state *s, DynamicViewCtx *view, InOutPuts *inouts) {
	char tmpbuf[128];
	InOutPutSum sumi;
	InOutPutSum sumo;

	DBTxCoinInfo *db = &view->db;
	SignRequest *msg = &s->req;

	if (msg->coin.type != COIN_TYPE_NEO) {
		db_error("invalid coin type:%d name:%s", msg->coin.type, msg->coin.uname);
		return -231;
	}
	const CoinConfig *coinConfig = getCoinConfig(msg->coin.type, msg->coin.uname);
	if (NULL == coinConfig) {
		db_error("invalid coin type:%d name:%s", msg->coin.type, msg->coin.uname);
		return -232;
	}
	storage_save_coin_info(coinConfig);

	if (gen_inout_summary(s, inouts, &sumi, &sumo, 0) != 0) {
		db_error("gen claim sum false");
		return -233;
	}
	if (sumi.neo_values != sumo.neo_values) {
		db_error("input neo_values:%lld != output neo_values:%lld", sumi.neo_values, sumo.neo_values);
		return -234;
	}
	if (sumo.change_type && sumo.change_type != coinConfig->id) {
		db_error("invalid change type:%d value:%lld", sumo.change_type, sumo.change_values);
		return -235;
	}
	if (coinConfig->id == ASSET_TYPE_GAS && sumi.neo_n) {
		db_error("GAS but have NEO input");
		return -236;
	}

	db_msg("tarns NEO input n:%d value:%lld  out n:%d value:%lld", sumi.neo_n, sumi.neo_values, sumo.neo_n, sumo.neo_values);
	db_msg("tarns GAS input n:%d value:%lld  out n:%d value:%lld", sumi.gas_n, sumi.gas_values, sumo.gas_n, sumo.gas_values);
	db_msg("change type:%d value:%lld", sumo.change_type, sumo.change_values);

	uint16_t coin_decimals = coinConfig->decimals;
	int64_t feed_value = sumi.gas_values - sumo.gas_values;
	int64_t send_value;
	int out_item_count;
	switch (coinConfig->id) {
		case ASSET_TYPE_NEO:
			send_value = sumi.neo_values - sumo.change_values;
			out_item_count = sumo.neo_n;
			view->coin_name = "NEO";
			break;
		case ASSET_TYPE_GAS:
			send_value = sumi.gas_values - sumo.change_values;
			out_item_count = sumo.gas_n;
			view->coin_name = "GAS";
			break;
		default:
			db_error("invalid asset:%d", coinConfig->type);
			return -237;
	}
	if (sumo.change_type) {
		out_item_count--;
	}

	const char *money_symbol = proto_get_money_symbol(&msg->exchange);
	db_msg("change_value:%lld feed_value:%lld", sumo.change_values, feed_value);

	int mScreenHeight = SCREEN_HEIGHT;
	int first_output_offset = SCREEN_HEIGHT;//res_getInt(MK_txs_sign, "first_output_offset", 0);
	int output_item_height = 105;//res_getInt(MK_txs_sign, "output_item_height", 0);
	if (!output_item_height) output_item_height = mScreenHeight;

	int num_perpage = mScreenHeight / output_item_height;

	//move ok to right pos
	int total_height = first_output_offset + mScreenHeight * ((out_item_count + num_perpage - 1) / num_perpage);

	db_msg("first_output_offset:%d output_item_height:%d out_item_count:%d total_height:%d num_perpage:%d",
	       first_output_offset, output_item_height, out_item_count, total_height, num_perpage);

	// view->total_height = total_height;
	// tx_set_db_view(coinConfig, db, view);
	view->coin_type = msg->coin.type;;
	view->coin_uname = msg->coin.uname;;
	view->coin_symbol = res_getLabel(LANG_LABEL_SEND);

	// view_add_txt(TXS_LABEL_UTX_TOTAL_TILE, res_getLabel(LANG_LABEL_TXS_VALUE_TITLE));
	format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_value, coin_decimals);
	view_add_txt(TXS_LABEL_UTX_TOTAL_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, view->coin_name);

	view_add_txt(TXS_LABEL_MAXID, "Chain:");
	view_add_txt(TXS_LABEL_MAXID, "NEO");
	// strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
	// snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", proto_coin_currency_value(&msg->exchange, send_value, coin_decimals));
	// strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));
	// snprintf(tmpbuf, sizeof(tmpbuf), "\xe2\x89\x88%s%s", money_symbol, db->currency_value);
	// view_add_txt(TXS_LABEL_UTX_TOTAL_MONEY, tmpbuf);

	int item_index = 0;
	for (int i = 0; i < inouts->output_n; i++) {
		if (inouts->outputs[i].flag & NEO_OUTPUT_FLAG_CHANGE) {
			continue;
		}
		if (check_asset_type(&inouts->outputs[i].asset) != coinConfig->id) {
			continue;
		}

		if (out_item_count > 1) {
			snprintf(tmpbuf, sizeof(tmpbuf), res_getLabel(LANG_LABEL_TXS_PAYTO_INDEX), item_index + 1);
		} else {
			strlcpy(tmpbuf, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE), sizeof(tmpbuf));
		}
		view_add_txt(TXS_LABEL_UTX_FEED_TILE, tmpbuf);
		if (is_empty_string(inouts->outputs[i].address)) {
			view_add_txt(TXS_LABEL_UTX_FEED_TILE, inouts->outputs[i].address);
		} else {
			view_add_txt(TXS_LABEL_UTX_FEED_TILE, inouts->outputs[i].address);
		}
		format_coin_real_value(tmpbuf, sizeof(tmpbuf), inouts->outputs[i].value, coin_decimals);
		view_add_txt(TXS_LABEL_UTX_FEED_TILE, tmpbuf);
		view_add_txt(TXS_LABEL_TOTAL_VALUE, view->coin_name);
		item_index++;
	}

	view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
	view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, s->myaddr);
	
	view_add_txt(TXS_LABEL_UTX_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
	format_coin_real_value(tmpbuf, sizeof(tmpbuf), feed_value, 8);
	view_add_txt(TXS_LABEL_UTX_FEED_VALUE, tmpbuf);
	view_add_txt(TXS_LABEL_TOTAL_VALUE, "GAS");
	return 0;
}

static int on_sign_show(void *session, DynamicViewCtx *view) {
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}
	int ret;
	struct pbc_rmessage *rmsg = s->client_msg->rmsg;
	InOutPuts inouts[1];

	db_msg("s->sign_type:%d", s->sign_type);

	if (s->sign_type & 4) {
		return show_invocation_tx(s, view, pbc_read_message(rmsg, "invocation_tx"));
	}
	
	if ((s->sign_type & 1) && neo_rmsg_InOutPuts(pbc_read_message(rmsg, "claim_tx"), inouts) == 0) {
		ret = show_claim_tx(s, view, inouts);
		neo_free_InOutPuts(inouts);
		return ret;
	}

	if ((s->sign_type & 2) && neo_rmsg_InOutPuts(pbc_read_message(rmsg, "contract_tx"), inouts) == 0) {
		ret = show_contract_tx(s, view, inouts);
		neo_free_InOutPuts(inouts);
		return ret;
	}
	db_error("invalid request,empty TX");
	return -108;
}

#endif
