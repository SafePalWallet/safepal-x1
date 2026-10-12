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
	TXS_LABEL_MEMO_TITLE,
	TXS_LABEL_MEMO_CONTENT,
	TXS_LABEL_ASSET_CODE_TITLE,
	TXS_LABEL_ASSET_CODE_VALUE,
	TXS_LABEL_ASSET_ISSUER_TITLE,
	TXS_LABEL_ASSET_ISSUER_VALUE,
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
		//issued-currency token coin.uname is a wallet-synthesized id absent from gCoinsConfig, fall back to the main chain config
		config = getCoinConfig(COIN_TYPE_XRP, "XRP");
	}
	if (!config) {
		db_error("get coin config false");
		return -201;
	}
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -1;
	}

	int coin_type = COIN_TYPE_XRP;
	// The config is always the XRP main-chain config for issued currencies.
	// Keep its uname for chain-level operations such as address derivation.
	const char *chain_uname = config->uname;
	const char *name = config->name;
	const char *symbol = config->symbol;

	//issued-currency detection matches get_req_message()/xrp_payment_serialize(): any of the three fields non-empty
	int isIssuedTx = !is_empty_string(msg->issuedAmount.currency) ||
	                 !is_empty_string(msg->issuedAmount.issuer) ||
	                 !is_empty_string(msg->issuedAmount.value);
	if (msg->tx_type == 0 && isIssuedTx) {
		//display name prefers token metadata (proto field 15), falls back to the on-chain currency code when the App omits it
		symbol = is_not_empty_string(msg->token.symbol) ? msg->token.symbol : msg->issuedAmount.currency;
		name = is_not_empty_string(msg->token.name) ? msg->token.name : symbol;
	}
	// Transaction history belongs to the issued asset, while address derivation
	// must remain on the XRP main chain.
	const char *asset_uname = (msg->tx_type == 0 && isIssuedTx) ? msg->coin.uname : chain_uname;

	db->coin_type = coin_type;
	strlcpy(db->coin_name, name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, asset_uname, sizeof(db->coin_uname));

	view->total_height = SCREEN_HEIGHT;
	view->coin_type = s->req.coin.type;
	view->coin_uname = s->req.coin.uname;
	view->coin_name = name;
	view->coin_symbol = symbol;

	if (msg->tx_type == 0) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
		double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
		const char *money_symbol = proto_get_money_symbol(&msg->exchange);
		double send_value;
		if (isIssuedTx) {
			//token payment: value is already a decimal string, show as-is without drops conversion
			send_value = 0;
			sscanf(msg->issuedAmount.value, "%lf", &send_value);
			strlcpy(tmpbuf, msg->issuedAmount.value, sizeof(tmpbuf));
		} else {
			send_value = ((double) msg->amount) / 1000000;
			snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", send_value);
		}
		db_msg("get send_value:%.8lf str:%s", send_value, tmpbuf);
		view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
	    view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

		view_add_txt(TXS_LABEL_MAXID, "Chain:");
		view_add_txt(TXS_LABEL_MAXID, config->name);

		strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));

		view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
		snprintf(tmpbuf, sizeof(tmpbuf), "%.8lf", ((double) msg->fee) / 1000000);
		view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
        view_add_txt(TXS_LABEL_TOTAL_VALUE, symbol);

		const char *tag = "Tag:";
		if (msg->destination_tag > 0) {
			snprintf(tmpbuf, sizeof(tmpbuf), "%s %u", tag, msg->destination_tag);
            view_add_txt(TXS_LABEL_TAG_CONTENT, tmpbuf);
        } else {
//			snprintf(tmpbuf, sizeof(tmpbuf), "%s ---", tag);
		}

		view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		ret = wallet_gen_address_by_path(tmpbuf, sizeof(tmpbuf), coin_type, chain_uname, msg->coin.path, 0);
		if (ret < 0) return ret;
		db_msg("my address ret:%d addr:%s", ret, tmpbuf);
		view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

		view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		view_add_txt(TXS_LABEL_PAYTO_ADDRESS, msg->destination);

		//memos: only the first memo_data is shown — the multi-memo blind-sign gap is recorded
		//in docs/known_issues.md. Printable bytes render as text, anything else as hex
		//(mirrors the memo branches in xlm_sign_view.c); format_data_to_hex_b truncates
		//oversized data as "head......tail"
		if (msg->memosCount > 0 && msg->memos && msg->memos[0].memoData.size > 0) {
			const ProtoBytes *memoData = &msg->memos[0].memoData;
            int printable = 1;
            for (int i = 0; i < memoData->size; i++) {
                unsigned char c = memoData->bytes[i];
                if ((c < 0x20 || c > 0x7E) && (c != '\r') && (c != '\n')) {
                    printable = 0;
                    break;
                }
            }
            memset(tmpbuf, 0, sizeof(tmpbuf));
			if (printable && memoData->size < (int) sizeof(tmpbuf)) {
				memcpy(tmpbuf, memoData->bytes, memoData->size);
				view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_TITLE));
			} else {
				format_data_to_hex_b(memoData->bytes, memoData->size, tmpbuf, sizeof(tmpbuf));
				view_add_txt(TXS_LABEL_MEMO_TITLE, res_getLabel(LANG_LABEL_TX_MEMO_HEX_TITLE));
			}
			view_add_txt(TXS_LABEL_MEMO_CONTENT, tmpbuf);
			view->total_height = 3 * SCREEN_HEIGHT;
		}
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
			view_add_txt(TXS_LABEL_MAXID, config->name);
			
			snprintf(db->send_value, sizeof(db->send_value), "%s", "Set MessageKey");
			view_add_txt(TXS_LABEL_ACCOUNTSET_TITLE, "Set MessageKey:");
			format_data_to_hex_b(msg->accountSet.MessageKey.bytes, msg->accountSet.MessageKey.size, tmpbuf, sizeof(tmpbuf));
			view_add_txt(TXS_LABEL_ACCOUNTSET_VALUE, tmpbuf);
		}
	} else if (msg->tx_type == 20) { //TrustSet: add/remove token from the App (layout mirrors xlm show_changeTrust)
		view->coin_symbol = name;
		strlcpy(db->coin_name, name, sizeof(db->coin_name));
		strlcpy(db->coin_symbol, name, sizeof(db->coin_symbol));

		const char *asset_code = is_not_empty_string(msg->token.symbol) ? msg->token.symbol : msg->trustSet.limitAmount.currency;
		//XRPL has no explicit add/remove field: a zero limit deletes the trustline, non-zero adds it
		int isRemove = 1;
		for (const char *p = msg->trustSet.limitAmount.value; p && *p; p++) {
			if (*p >= '1' && *p <= '9') {
				isRemove = 0;
				break;
			}
		}
		if (isRemove) {
			view->coin_symbol = res_getLabel(LANG_LABEL_XLM_DISTRUST_ASSET);
			snprintf(tmpbuf, sizeof(tmpbuf), "- %s", asset_code);
		} else {
			view->coin_symbol = res_getLabel(LANG_LABEL_XLM_TRUST_ASSET);
			snprintf(tmpbuf, sizeof(tmpbuf), "+ %s", asset_code);
		}
		strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));

		view_add_txt(TXS_LABEL_ASSET_CODE_TITLE, res_getLabel(LANG_LABEL_XLM_ASSET_CODE));
		view_add_txt(TXS_LABEL_ASSET_CODE_VALUE, asset_code);
		view_add_txt(TXS_LABEL_ASSET_ISSUER_TITLE, res_getLabel(LANG_LABEL_XLM_ASSET_ISSUER));
		view_add_txt(TXS_LABEL_ASSET_ISSUER_VALUE, msg->trustSet.limitAmount.issuer);
	} else {
		db_error("invalid tx_type:%d", msg->tx_type);
		return -1;
	}

	//save coin info
	if (view->msg_from == MSG_FROM_QR_APP) {
		if (msg->tx_type == 0 && isIssuedTx) {
			// The fallback config describes the XRP chain, not the issued token.
			// Store the wallet-synthesized token uname and its display metadata so
			// the token appears in the home asset list.
			if (is_empty_string(msg->coin.uname)) {
				db_error("issued payment has empty coin uname");
				return -1;
			}
			if (!storage_isCoinExist(coin_type, msg->coin.uname)) {
				DBCoinInfo dbinfo;
				memset(&dbinfo, 0, sizeof(dbinfo));
				dbinfo.type = (uint16_t) coin_type;
				dbinfo.curv = config->curv;
				dbinfo.decimals = msg->token.decimals;
				strncpy(dbinfo.uname, msg->coin.uname, COIN_UNAME_MAX_LEN);
				strncpy(dbinfo.name, name, COIN_NAME_MAX_LEN);
				strncpy(dbinfo.symbol, symbol, COIN_SYMBOL_MAX_LEN);
				storage_save_coin_dbinfo(&dbinfo);
			}
		} else {
			storage_save_coin_info(config);
		}
	}
	return 0;
}

#endif