#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Multiversx/multiversx_sign.c"

#endif

#include "coin_util_hw.h"
#include "storage_manager.h"
#include "dynamic_win.h"


static int on_sign_show(void *session, DynamicViewCtx *view) {
	char tmpbuf[128];
	int coin_type = 0;
	const char *coin_uname = NULL;
	const char *name = NULL;
	const char *symbol = NULL;
	int ret;
	uint8_t coin_decimals = 0;
	
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	MultiversxSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));
	memset(tmpbuf, 0, sizeof(tmpbuf));

	coin_type = msg->coin.type;
	coin_uname = msg->coin.uname;
	if ((char)msg->operation_type==OP_TYPE_MTOKEN) {
		if (is_empty_string(msg->token.name) || is_empty_string(msg->token.symbol)) {
			db_error("invalid dtoken name:%s or symbol:%s", msg->token.name, msg->token.symbol);
			return -1;
		}
		
		name = msg->token.name;
		symbol = msg->token.symbol;
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
	
	const CoinConfig *mainConfig = getCoinConfig(msg->coin.type, "EGLD");
	if (!mainConfig) {
		db_msg("not mainConfig type:%d", msg->coin.type);
		return -1;
	}

	if (((char) msg->operation_type == OP_TYPE_MTOKEN) || \
        ((char) msg->operation_type == OP_TYPE_MCOIN) ) {

		if ((char) msg->operation_type == OP_TYPE_MCOIN) {
			coin_decimals = 18;
		} else if ((char) msg->operation_type == OP_TYPE_MTOKEN) {
			coin_decimals = msg->token.decimals;
		}

		view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
		if (proto_check_exchange(&msg->exchange) != 0) {
			db_error("invalid exchange");
			return -1;
		}

		view_add_txt(0, msg->action.sendCoins.valueStr);
		view_add_txt(0, symbol);

		if (mainConfig) {
			view_add_txt(0, "Chain:");
			view_add_txt(0, mainConfig->name);
		}

		view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
	    omit_string(tmpbuf, msg->action.sendCoins.sender, 26, 11);
		view_add_txt(0, tmpbuf);

		view_add_txt(0, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
		omit_string(tmpbuf, msg->action.sendCoins.receiver, 26, 11);
		view_add_txt(0, tmpbuf);


		view_add_txt(0, msg->action.sendCoins.fee);
		view_add_txt(0, mainConfig->symbol);

		if ((char) msg->operation_type == OP_TYPE_MCOIN) {
			const char *memo = msg->action.sendCoins.memo;
			if (is_printable_str(memo)) {
				view_add_txt(0, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
				view_add_txt(0, memo);
			} else {
				view_add_txt(0, res_getLabel(LANG_LABEL_TX_MEMO_HEX_TITLE));
				ret = strlen(memo);
				if (ret * 2 < (int) sizeof(tmpbuf)) {
					bin_to_hex((const unsigned char *)memo, ret, tmpbuf);
					view_add_txt(0, tmpbuf);
				} else {
					char *hex = (char *) malloc((ret + 1) * 2);
					if (hex) {
						memset(hex, 0, (ret + 1) * 2);
						bin_to_hex((const unsigned char *)memo, ret, hex);
						view_add_txt(0, hex);
						free(hex);
					}
				}
			}
		}
	} else if ((char) msg->operation_type == OP_TYPE_DAPP) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SIGN_TRANSACTION);
		db->tx_type = TX_TYPE_APP_SIGN_MSG;
		view_add_txt(0, "DApp:");
		view_add_txt(0, symbol);

		if (mainConfig) {
			view_add_txt(0, "Chain:");
			view_add_txt(0, mainConfig->name);
		}

		view_add_txt(0, "Data:");
		view_add_txt(0, msg->action.dapp.displayStr);
	} else if ((char) msg->operation_type == OP_TYPE_MSG) {
		view->coin_symbol = "Sign Message";
		db->tx_type = TX_TYPE_APP_SIGN_MSG;
		view_add_txt(0, "DApp:");
		view_add_txt(0, symbol);

		if (mainConfig) {
			view_add_txt(0, "Chain:");
			view_add_txt(0, mainConfig->name);
		}

		view_add_txt(0, "Data:");
		// view_add_txt(0, msg->action.msg.displayStr);
		const char *message = msg->action.msg.serialize;
		omit_string(tmpbuf, message, 50, 50);
		view_add_txt(0, tmpbuf);
	}  else {

	}


	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = name;

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
