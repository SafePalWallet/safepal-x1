#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Solana/sol_sign.c"

#endif

#include "coin_util_hw.h"
#include "storage_manager.h"
#include "dynamic_win.h"

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
	char tmpbuf[128];
	uint64_t send_amount = 0;
	int coin_type = 0;
	const char *coin_uname = NULL;
	const char *name = NULL;
	const char *symbol = NULL;
	double send_value = 0;
	int ret;
	char str[128];
	uint8_t coin_decimals = 0;
	
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	SolSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));
	memset(tmpbuf, 0, sizeof(tmpbuf));


#if 0
	db_msg("-------------------------------");
	db_msg("msg->coin.type:%x", (int)msg->coin.type);
	db_msg("msg->coin.uname:%s", msg->coin.uname);
	db_msg("msg->exchange.amount:%d", (int)msg->exchange.amount);
	db_msg("msg->exchange.currency:%s", msg->exchange.currency);
	db_msg("msg->exchange.symbol:%s", msg->exchange.symbol);
	db_msg("msg->exchange.value:%lld", (unsigned long long)msg->exchange.value);
	
	if((char)msg->operation_type == OP_TYPE_TRANSFER){
		db_msg("msg->action.transfer.recipient:%s", msg->action.transfer.recipient);
		db_msg("msg->action.transfer.value:%lld", (long long)msg->action.transfer.value);
	}
	else if(((char)msg->operation_type==OP_TYPE_TOKENTRANSFER) || \
		((char)msg->operation_type==OP_TYPE_CREATE_AND_TRANSFER)){
		db_msg("msg->action.token_transfer.to:%s", msg->action.token_transfer.to);
		db_msg("msg->action.token_transfer.tokenMintAddress:%s", msg->action.token_transfer.token_mint_address);
		db_msg("msg->action.token_transfer.sender_token_address:%s", msg->action.token_transfer.sender_token_address);
		db_msg("msg->action.token_transfer.recipient_token_address:%s", msg->action.token_transfer.recipient_token_address);
		db_msg("msg->action.token_transfer.amount:%lld", (long long)msg->action.token_transfer.amount);
		db_msg("msg->action.token_transfer.decimals:%d", (int)msg->action.token_transfer.decimals);
	}
	else if((char)msg->operation_type == OP_TYPE_DAPP){
		db_msg("msg->action.dapp.app_name:%s", msg->action.dapp.app_name);
		db_msg("msg->action.dapp.message_data.size:%d", msg->action.dapp.message_data.size);
		db_msg("msg->action.dapp.type:%d", msg->action.dapp.type);
	} 
	else if(((char)msg->operation_type==OP_TYPE_NFT_TRANSFER) || \
		((char)msg->operation_type==OP_TYPE_NFT_CREATE_AND_TRANSFER)){
		db_msg("msg nft  app_name:%s", msg->action.token_transfer.app_name);
		db_msg("msg nft  to:%s", msg->action.token_transfer.to);
		db_msg("msg nft  tokenMintAddress:%s", msg->action.token_transfer.token_mint_address);
		db_msg("msg nft  sender_token_address:%s", msg->action.token_transfer.sender_token_address);
		db_msg("msg nft  recipient_token_address:%s", msg->action.token_transfer.recipient_token_address);
		db_msg("msg nft  amount:%lld", (long long)msg->action.token_transfer.amount);
		db_msg("msg nft  decimals:%d", (int)msg->action.token_transfer.decimals);
		db_msg("msg nft  fee:%d", (int)msg->action.token_transfer.fee);
		db_msg("msg nft transfer  fee:%d", (int)msg->action.transfer.fee);
	}
	db_msg("-------------------------------");
#endif

	coin_type = msg->coin.type;
	coin_uname = msg->coin.uname;
	if (((char)msg->operation_type==OP_TYPE_TOKENTRANSFER) || ((char)msg->operation_type==OP_TYPE_CREATE_AND_TRANSFER)) {
		if (is_empty_string(msg->token.name) || is_empty_string(msg->token.symbol)) {
			db_error("invalid dtoken name:%s or symbol:%s", msg->token.name, msg->token.symbol);
			return -1;
		}
		
		name = msg->token.name;
		symbol = msg->token.symbol;
	} else if (((char)msg->operation_type==OP_TYPE_NFT_TRANSFER) || ((char)msg->operation_type==OP_TYPE_NFT_CREATE_AND_TRANSFER)) {
		if (is_empty_string(msg->action.token_transfer.app_name) || is_empty_string(msg->action.token_transfer.app_name)) {
			db_error("msg->action.token_transfer.app_name null");
			return -1;
		}
		
		name = msg->action.token_transfer.app_name;
		symbol = msg->action.token_transfer.app_name;
	} else if((char)msg->operation_type==OP_TYPE_DAPP ){
		name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
		symbol = msg->action.dapp.app_name;
	} else if((char)msg->operation_type==OP_TYPE_MSG){
		name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
		symbol = msg->action.msg.app_name;
	} else{
		const CoinConfig *config = getCoinConfig(msg->coin.type, msg->coin.uname);
		if (!config) {
			db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
			name = msg->coin.uname;
			symbol = msg->coin.uname;
		}else{
			name = config->name;
			symbol = config->symbol;
		}
	}
	
	const CoinConfig *mainConfig = getCoinConfig(msg->coin.type, "SOL");
	if (!mainConfig) {
		db_msg("not mainConfig type:%d", msg->coin.type);
		return -1;
	}

	if (((char) msg->operation_type == OP_TYPE_TRANSFER) || \
        ((char) msg->operation_type == OP_TYPE_TOKENTRANSFER) || \
        ((char) msg->operation_type == OP_TYPE_CREATE_AND_TRANSFER)) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
		if (proto_check_exchange(&msg->exchange) != 0) {
			db_error("invalid exchange");
			return -1;
		}
		double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
		const char *money_symbol = proto_get_money_symbol(&msg->exchange);

		db_msg("ex_rate:%f", ex_rate);
		db_msg("money_symbol:%s", money_symbol);

		if ((char) msg->operation_type == OP_TYPE_TRANSFER) {
			send_amount = msg->action.transfer.value;
			send_value = ((double) send_amount) / 1000000000;
			coin_decimals = 9;
		} else if (((char) msg->operation_type == OP_TYPE_TOKENTRANSFER) || \
            ((char) msg->operation_type == OP_TYPE_CREATE_AND_TRANSFER)) {
			send_amount = msg->action.token_transfer.amount;
			send_value = proto_coin_real_value(send_amount, msg->action.token_transfer.decimals);
			coin_decimals = msg->action.token_transfer.decimals;
		}

		db_msg("send_value:%.8lf", send_value);

		memset(tmpbuf, 0, sizeof(tmpbuf));
		snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", send_value);
		view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

		// strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
		// snprintf(db->currency_value, sizeof(db->currency_value), "%.2f", ex_rate * send_value);
		// snprintf(tmpbuf, sizeof(tmpbuf), "\xe2\x89\x88%s%.2f", money_symbol, ex_rate * send_value);
		// view_add_txt(TXS_LABEL_TOTAL_MONEY, tmpbuf);
		// strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

		if (mainConfig) {
			view_add_txt(TXS_LABEL_MAXID, "Chain:");
			view_add_txt(TXS_LABEL_MAXID, mainConfig->name);
		}

		view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		const char *uname2 = coin_uname;
		if (strcmp(msg->coin.path, sol_get_hd_path(COIN_TYPE_SOLANA, COIN_UNAME_SOL2)) == 0) {
			uname2 = COIN_UNAME_SOL2;
		}
		wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, uname2, 0, 0);
		omit_string(tmpbuf, tmpbuf, 26, 11);
		view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

		view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));

		omit_string(tmpbuf, msg->action.transfer.recipient, 26, 11);
		view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

		view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
		send_amount = 0;
		if ((char) msg->operation_type == OP_TYPE_TRANSFER) {
			send_amount = msg->action.transfer.fee;
		} else if (((char) msg->operation_type == OP_TYPE_TOKENTRANSFER) || \
            ((char) msg->operation_type == OP_TYPE_CREATE_AND_TRANSFER)) {
			send_amount = msg->action.token_transfer.fee;
		}
		format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_amount, 9);
		view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_MAXID, mainConfig->symbol);

	} else if (((char) msg->operation_type == OP_TYPE_NFT_TRANSFER) || \
        ((char) msg->operation_type == OP_TYPE_NFT_CREATE_AND_TRANSFER)) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND_NFT);
		view_add_txt(TXS_LABEL_MAXID, symbol);

		view_add_txt(TXS_LABEL_TOTAL_VALUE, "Token address");

		char tmpbuf[128];
		memset(tmpbuf, 0, sizeof(tmpbuf));
		memcpy(tmpbuf, msg->action.token_transfer.token_mint_address, 7);
		tmpbuf[7] = '.';
		tmpbuf[8] = '.';
		tmpbuf[9] = '.';
		int len = strlen(msg->action.token_transfer.token_mint_address);
		memcpy(tmpbuf + 10, msg->action.token_transfer.token_mint_address + (len - 8), 8);
		db_msg("tmpbuf:%s", tmpbuf);
		view_add_txt(TXS_LABEL_TOTAL_MONEY, tmpbuf);

		view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		const char *uname2 = coin_uname;
		if (strcmp(msg->coin.path, sol_get_hd_path(COIN_TYPE_SOLANA, COIN_UNAME_SOL2)) == 0) {
			uname2 = COIN_UNAME_SOL2;
		}
		wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, uname2, 0, 0);
		omit_string(tmpbuf, tmpbuf, 26, 11);
		view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

		view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
		omit_string(tmpbuf, msg->action.transfer.recipient, 26, 11);
		view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

		view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
		send_amount = msg->action.token_transfer.fee;
		format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_amount, 9);
		view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_MAXID, mainConfig->symbol);
	} else if ((char) msg->operation_type == OP_TYPE_DAPP) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SIGN_TRANSACTION);
		db->tx_type = TX_TYPE_APP_SIGN_MSG;
		view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
		view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

		if (mainConfig) {
			view_add_txt(TXS_LABEL_MAXID, "Chain:");
			view_add_txt(TXS_LABEL_MAXID, mainConfig->name);
		}

		view_add_txt(TXS_LABEL_APP_MSG_VALUE, "Data:");
		format_data_to_hex(msg->action.dapp.message_data.bytes, msg->action.dapp.message_data.size, str, sizeof(str));
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, str);
	} else if ((char) msg->operation_type == OP_TYPE_MSG) {
		view->coin_symbol = "Sign Message";
		db->tx_type = TX_TYPE_APP_SIGN_MSG;
		view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
		view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

		if (mainConfig) {
			view_add_txt(TXS_LABEL_MAXID, "Chain:");
			view_add_txt(TXS_LABEL_MAXID, mainConfig->name);
		}

		view_add_txt(TXS_LABEL_APP_MSG_VALUE, "Data:");
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, msg->action.msg.message);
	} else {

	}


	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = name;
	// view->coin_symbol = symbol;

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


#endif
