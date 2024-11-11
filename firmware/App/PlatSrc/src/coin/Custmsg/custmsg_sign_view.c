#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Custmsg/custmsg_sign.c"

#endif

#include "coin_util_hw.h"

enum {
	TXS_LABEL_TITLE1,
	TXS_LABEL_VALUE1,
	TXS_LABEL_TITLE2,
	TXS_LABEL_VALUE2,
	TXS_LABEL_TITLE3,
	TXS_LABEL_AMOUNT,
	TXS_LABEL_MEMO_TITLE,
	TXS_LABEL_MEMO_VALUE,
	TXS_LABEL_CKEY_VALUE,
	TXS_LABEL_SIGN_MSG,
	TXS_LABEL_SIGN_MSG2,
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
	CustmsgSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;
	memset(db, 0, sizeof(DBTxCoinInfo));

	view->flag |= 0x1;

    const CoinConfig *config = getCoinConfig(msg->coin.type, msg->coin.uname);
    if (!config) {
        if (msg->coin.type != COIN_TYPE_CUSTOM_EVM && msg->coin.category != COIN_CATEGORY_EVM) {
            db_error("invalid coin");
            return -2;
        }
    }

	int coin_type = msg->coin.type;
	db->coin_type = coin_type;

	if (is_not_empty_string(msg->app_name) && msg->msg_type != CUST_MSG_TYPE_WITHDRAW && msg->msg_type != CUST_MSG_TYPE_LOGIN) {
		strlcpy(db->coin_uname, msg->app_name, sizeof(db->coin_uname));
		view_add_txt(TXS_LABEL_TITLE1, "DApp:");
		view_add_txt(TXS_LABEL_VALUE1, msg->app_name);
	} else {
		strlcpy(db->coin_uname, msg->coin.uname, sizeof(db->coin_uname));
	}
	db_msg("coin %d uname:%s app_name:%s,msg_type:%d", db->coin_type, db->coin_uname, msg->app_name,msg->msg_type);

	if (config && msg->msg_type != CUST_MSG_TYPE_WITHDRAW && msg->msg_type != CUST_MSG_TYPE_LOGIN) {
		view_add_txt(TXS_LABEL_TITLE1, "Chain:");
		view_add_txt(TXS_LABEL_VALUE1, config->name);
	}
		
	if (msg->msg_type == CUST_MSG_TYPE_TXT) {
		db->tx_type = TX_TYPE_SIGN_MSG;
		//snprintf(db->coin_symbol, sizeof(db->coin_symbol), "%s %s", config->symbol, res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG));
		snprintf(db->coin_symbol, sizeof(db->coin_symbol), "%s", res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG));
		view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
	} else if (msg->msg_type == CUST_MSG_TYPE_LOGIN) {
		db->tx_type = TX_TYPE_LOGIN;
		snprintf(db->coin_symbol, sizeof(db->coin_symbol), "%s %s", msg->app_name, res_getLabel(LANG_LABEL_TX_METHOD_LOGIN));
		view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_LOGIN);
	} else if (msg->msg_type == CUST_MSG_TYPE_WITHDRAW) {
		db->tx_type = TX_TYPE_WITHDRAW;
		snprintf(db->coin_symbol, sizeof(db->coin_symbol), "%s %s", msg->app_name, res_getLabel(LANG_LABEL_TX_METHOD_WITHDRAW));
		view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_WITHDRAW);
	}else if(msg->msg_type == CUST_MSG_TYPE_TYPEDDATA){
		strlcpy(db->coin_uname, "Dapp", sizeof(db->coin_uname));
        db->tx_type = TX_TYPE_APP_APPROVAL;
        snprintf(db->coin_symbol, sizeof(db->coin_symbol), "%s", res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG));
		view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
    } else if (msg->msg_type == CUST_MSG_TYPE_AUTH) {
        db->tx_type = TX_TYPE_APP_APPROVAL;
        snprintf(db->coin_symbol, sizeof(db->coin_symbol), "%s %s", msg->app_name, "Authorize");
		view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
    }

    view->total_height = SCREEN_HEIGHT;
	view->coin_type = db->coin_type;
	view->coin_uname = db->coin_uname;
	view->coin_name = db->coin_name;
//	view->coin_symbol = db->coin_symbol;

	db_msg("msg->msg_type:%d",msg->msg_type);
	if (msg->msg_type == CUST_MSG_TYPE_TXT) {
		int offset = -27;
		view_add_txt_off(TXS_LABEL_TITLE2, res_getLabel(LANG_LABEL_TXT_ADDRESS), offset);
		view_add_txt_off(TXS_LABEL_VALUE2, msg->my_address, offset);

		snprintf(tmpbuf, sizeof(tmpbuf), "%s:", res_getLabel(LANG_LABEL_TX_MESSAGE));
		view_add_txt_off(TXS_LABEL_TITLE3, tmpbuf, offset);
		if (msg->bin_msg.size > 0) {
			if (msg->bin_msg.size > 48) {
				view->total_height = SCREEN_HEIGHT * 2;
				format_data_to_hex(msg->bin_msg.bytes, msg->bin_msg.size, tmpbuf, sizeof(tmpbuf));
				view_add_txt(TXS_LABEL_SIGN_MSG2, tmpbuf);
			} else {
				tmpbuf[0] = '0';
				tmpbuf[1] = 'x';
				bin_to_hex(msg->bin_msg.bytes, msg->bin_msg.size, tmpbuf + 2);
				snprintf(db->send_value, sizeof(db->send_value), "%s", tmpbuf);
				view_add_txt(TXS_LABEL_SIGN_MSG, tmpbuf);
			}
		} else {
			snprintf(db->send_value, sizeof(db->send_value), "%s", msg->msg);
			if (strlen(msg->msg) > 100) {
				view->total_height = SCREEN_HEIGHT * 2;
				if (strlen(msg->msg) > sizeof(tmpbuf)) {
					strncpy(tmpbuf, msg->msg, (sizeof(tmpbuf) - 8));
					tmpbuf[(sizeof(tmpbuf) - 8)] = 0;
					strcat(tmpbuf, "......");
					view_add_txt(TXS_LABEL_SIGN_MSG2, tmpbuf);
				} else {
					view_add_txt(TXS_LABEL_SIGN_MSG2, msg->msg);
				}
			} else {
				view_add_txt(TXS_LABEL_SIGN_MSG, msg->msg);
			}
		}
    } else if ((msg->msg_type == CUST_MSG_TYPE_LOGIN) || (msg->msg_type == CUST_MSG_TYPE_AUTH)) {
		view_add_txt(TXS_LABEL_VALUE1, msg->app_name);
		view_add_txt(TXS_LABEL_TITLE2, res_getLabel(LANG_LABEL_TXT_ADDRESS));
		view_add_txt(TXS_LABEL_VALUE2, msg->my_address);
		snprintf(tmpbuf, sizeof(tmpbuf), "%s:", res_getLabel(LANG_LABEL_TX_MESSAGE));
		view_add_txt(TXS_LABEL_TITLE3, tmpbuf);
		view_add_txt(TXS_LABEL_CKEY_VALUE, msg->msg);
		snprintf(db->send_value, sizeof(db->send_value), "%s", msg->msg);
	} else if (msg->msg_type == CUST_MSG_TYPE_WITHDRAW) {
		int off = 0;
		if (!strcmp(msg->withdraw.coin_name, "XLM")) {
			off = 15;
		}
		// view_add_txt_off(TXS_LABEL_TITLE3, res_getLabel(LANG_LABEL_ORDER_AMOUNT), off);
		double quantity = ((double) msg->withdraw.value) / 100000000;
		snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", quantity);
		pretty_float_string(tmpbuf, 1);
		view_add_txt_off(TXS_LABEL_AMOUNT, tmpbuf, off);
		snprintf(db->send_value, sizeof(db->send_value), "%s %s", tmpbuf, msg->withdraw.coin_name);

		snprintf(tmpbuf, sizeof(tmpbuf), "%s", msg->withdraw.coin_name);
		view_add_txt(TXS_LABEL_VALUE1, tmpbuf);

	    // view_add_txt(TXS_LABEL_TITLE1, "Chain:");
		// view_add_txt(TXS_LABEL_VALUE1, config->name);

		view_add_txt(TXS_LABEL_TITLE2, res_getLabel(LANG_LABEL_RECEIVE_ADDRESS));
		view_add_txt(TXS_LABEL_VALUE2, msg->withdraw.addrss);

		if (is_not_empty_string(msg->withdraw.address_tag)) {
			view->total_height += SCREEN_HEIGHT;
			snprintf(tmpbuf, sizeof(tmpbuf), "%s:", is_not_empty_string(msg->withdraw.tag_name) ? msg->withdraw.tag_name : "Tag");
			view_add_txt(TXS_LABEL_MEMO_TITLE, tmpbuf);
			view_add_txt(TXS_LABEL_MEMO_VALUE, msg->withdraw.address_tag);
		}
	}else if(msg->msg_type == CUST_MSG_TYPE_TYPEDDATA) {
		int offset = -27;
		view_add_txt_off(TXS_LABEL_TITLE2, res_getLabel(LANG_LABEL_TXT_ADDRESS), offset);
		view_add_txt_off(TXS_LABEL_VALUE2, msg->my_address, offset);

		snprintf(tmpbuf, sizeof(tmpbuf), "%s:", res_getLabel(LANG_LABEL_TX_MESSAGE));
		view_add_txt_off(TXS_LABEL_TITLE3, tmpbuf, offset);
		snprintf(db->send_value, sizeof(db->send_value), "%s", msg->typed_data.display_msg);
		if (strlen(msg->typed_data.display_msg) > 100) {
			view->total_height = SCREEN_HEIGHT * 2;
			if (strlen(msg->typed_data.display_msg) > sizeof(tmpbuf)) {
				strncpy(tmpbuf, msg->typed_data.display_msg, (sizeof(tmpbuf) - 8));
				tmpbuf[(sizeof(tmpbuf) - 8)] = 0;
				strcat(tmpbuf, "......");
				view_add_txt(TXS_LABEL_SIGN_MSG2, tmpbuf);
			} else {
				view_add_txt(TXS_LABEL_SIGN_MSG2, msg->typed_data.display_msg);
			}
		} else {
			view_add_txt(TXS_LABEL_SIGN_MSG, msg->typed_data.display_msg);
		}
	}

	return 0;
}

#endif

