#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Ethereum/eth_sign.c"
#endif
#include "coin_config.h"
#include "coin_util_hw.h"

enum {
	TXS_LABEL_TOTAL_VALUE,
	TXS_LABEL_TOTAL_MONEY,
	TXS_LABEL_NFT_ID_TITLE,
	TXS_LABEL_NFT_ID_VALUE,
	TXS_LABEL_NFT_AMOUNT_TITLE,
	TXS_LABEL_NFT_AMOUNT_VALUE,
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
	TXS_LABEL_APPROVE_TOKEN_TITLE,
	TXS_LABEL_APPROVE_TOKEN_VALUE,
	TXS_LABEL_APPROVE_AMOUNT_TITLE,
	TXS_LABEL_APPROVE_AMOUNT_VALUE,
	TXS_LABEL_SIMPLE_FEE_TITLE,
	TXS_LABEL_SIMPLE_FEE_VALUE,
	TXS_LABEL_APP_MSG_VALUE,
	TXS_LABEL_MAXID,
};

static int on_sign_show(void *session, DynamicViewCtx *view) {
	char tmpbuf[256], disp[32] = {0};
	coin_state *s = (coin_state *) session;
	if (!s) {
		db_error("invalid session");
		return -1;
	}

	int ret;
	EthSignTxReq *msg = &s->req;
	DBTxCoinInfo *db = &view->db;

	memset(db, 0, sizeof(DBTxCoinInfo));
	if (proto_check_exchange(&msg->exchange) != 0) {
		db_error("invalid exchange");
		return -102;
	}

	double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
	const char *money_symbol = proto_get_money_symbol(&msg->exchange);

	int coin_type = 0;
	const char *coin_uname = "";
	const char *name = "";
	const char *symbol = "";
	uint8_t coin_decimals = 0;
	uint8_t is_transfer = 0;
	uint8_t is_transfer_from = 0;
	uint8_t is_1155_transfer = 0;
	uint8_t is_approval = 0;
	uint8_t trans_token = 0;
	uint8_t trans_nft = 0;
	uint8_t detected_data = 0;
	const CoinConfig *config = NULL;
	do {
		detected_data = 1;
		//transfer(address _to, uint256 _value)     //ERC20
		//transfer(address _to, uint256 _tokenId)   //ERC721
		if (msg->to.size == 20 && msg->value.size == 0 && msg->data.size == 68
		    && memcmp(msg->data.bytes, "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {
			is_transfer = 1;
			trans_token = 1;
            if (msg->token.type == COIN_TYPE_ERC721 ||
                msg->token.type == COIN_TYPE_BEP721 ||
                msg->token.type == COIN_TYPE_FANTOM721 ||
                msg->token.type == COIN_TYPE_HECO721 ||
                msg->token.type == COIN_TYPE_OPTIMISM721 ||
                msg->token.type == COIN_TYPE_ARBITRUM721 ||
                msg->token.type == COIN_TYPE_AVAX721 ||
                msg->token.type == COIN_TYPE_POLYGON721 ||
                msg->token.type == COIN_TYPE_GODWOKENV1_721 ||
                msg->token.type == COIN_TYPE_KLAYTN_721 ||
				msg->token.type == COIN_TYPE_TLOS_721 ||
				msg->token.type == COIN_TYPE_ZKSYNC_721 ||
				msg->token.type == COIN_TYPE_PZK_721 ||
				msg->token.type == COIN_TYPE_PLS_721 ||
				msg->token.type == COIN_TYPE_CMP_721 ||
                msg->token.type == COIN_TYPE_CUSTOM_EVM_721) {
				trans_nft = 1;
			}
			break;
		}

		//transferFrom(address src, address dst, uint256 amount) MethodID: 0x23b872dd
		if (msg->to.size == 20 && msg->value.size == 0 && msg->data.size == 100
		    && memcmp(msg->data.bytes, "\x23\xb8\x72\xdd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {
			is_transfer_from = 1;
			trans_token = 1;
            if (msg->token.type == COIN_TYPE_ERC721 ||
                msg->token.type == COIN_TYPE_BEP721 ||
                msg->token.type == COIN_TYPE_FANTOM721 ||
                msg->token.type == COIN_TYPE_HECO721 ||
                msg->token.type == COIN_TYPE_OPTIMISM721 ||
                msg->token.type == COIN_TYPE_ARBITRUM721 ||
                msg->token.type == COIN_TYPE_AVAX721 ||
                msg->token.type == COIN_TYPE_POLYGON721 ||
                msg->token.type == COIN_TYPE_GODWOKENV1_721 ||
                msg->token.type == COIN_TYPE_KLAYTN_721 ||
				msg->token.type == COIN_TYPE_TLOS_721 ||
				msg->token.type == COIN_TYPE_ZKSYNC_721 ||
				msg->token.type == COIN_TYPE_PLS_721 ||
				msg->token.type == COIN_TYPE_PZK_721 ||
				msg->token.type == COIN_TYPE_CMP_721 ||
                msg->token.type == COIN_TYPE_CUSTOM_EVM_721) {
                trans_nft = 1;
            }
			break;
		}

		//0xf242432a safeTransferFrom(address _from, address _to, uint256 _id, uint256 _amount, bytes _data) //ERC1155
		if (msg->to.size == 20 && msg->value.size == 0 && msg->data.size >= 164
		    && memcmp(msg->data.bytes, "\xf2\x42\x43\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {
			is_1155_transfer = 1;
			trans_token = 1;
			trans_nft = 1;
			break;
		}

		//0x095ea7b3 approve(address spender, uint256 amount)
		if (msg->data.size == 68 && memcmp(msg->data.bytes, "\x09\x5e\xa7\xb3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {
			is_approval = 1;
			if (msg->sign_type != 1) {
				db_error("invalid sign type:%d", msg->sign_type);
				return -103;
			}
			break;
		}

		detected_data = 0;
	} while (0);

	if (msg->sign_type == 1) {
		if (!is_approval) {
			db_error("invalid sign data");
			return -104;
		}
		if (is_empty_string(msg->contract.name)) {
			db_error("invalid contract name");
			return -105;
		}
		if (msg->contract.id.size != 20) {
			db_error("invalid contract id:%d", msg->contract.id.size);
			return -106;
		}
		if (memcmp(msg->data.bytes + 16, msg->contract.id.bytes, 20) != 0) {
			db_error("missmatch contract id and data");
			return -107;
		}
	} else if (msg->sign_type == 2) { //app
		if (msg->data.size < 4) {
			db_error("invalid data size:%d", msg->data.size);
			return -113;
		}
		if (is_empty_string(msg->contract.name)) {
			db_error("invalid contract name");
			return -115;
		}
		if (msg->contract.id.size != 20) {
			db_error("invalid contract id");
			return -116;
		}
		if (msg->to.size != 20) {
			db_error("invalid to size:%d", msg->to.size);
			return -117;
		}
		if (memcmp(msg->to.bytes, msg->contract.id.bytes, 20) != 0) {
			db_error("missmatch contract id and to");
			return -118;
		}
	}

	if (msg->coin.type && is_not_empty_string(msg->coin.uname)) {
		config = getCoinConfig(msg->coin.type, msg->coin.uname);
		if (!config) {
			db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
		}
	}

	if (config) {
		name = config->name;
		symbol = config->symbol;
		coin_decimals = config->decimals;
		coin_type = config->type;
		coin_uname = config->uname;
	} else if (trans_token && msg->token.type) {
		if (msg->coin.type && msg->token.type != msg->coin.type) {
			db_error("invalid coin.type:%d token.type:%d", msg->coin.type, msg->token.type);
			return -1;
		}
		if (is_empty_string(msg->token.name) || is_empty_string(msg->token.symbol)) {
            if (trans_nft) {//NFT not has name or symbol
                //run
            } else {
                db_error("invalid dtoken name:%s or symbol:%s", msg->token.name, msg->token.symbol);
                return -1;
            }
		}
		if (msg->token.decimals < 0 || msg->token.decimals > 40) {
			db_error("invalid decimals:%d", msg->token.decimals);
			return -1;
		}
		name = msg->token.name;
		symbol = msg->token.symbol;
		if ((msg->token.type == msg->coin.type) && is_not_empty_string(msg->coin.uname)) {
			coin_uname = msg->coin.uname;
			const char *coin_uname_err = NULL;
			if (strlen(name) < COIN_UNAME_BUFFSIZE) {
				coin_uname_err = name;
			} else {
				coin_uname_err = symbol;
			}
			//clean invalid old data
			if ((view->msg_from == MSG_FROM_QR_APP) && is_not_empty_string(coin_uname_err) && strcmp(coin_uname, coin_uname_err) != 0) {
				if (storage_isCoinExist(msg->token.type, coin_uname_err) > 0) {
					storage_deleteCoinInfo(msg->token.type, coin_uname_err);
				}
			}
		} else if (strlen(name) < COIN_UNAME_BUFFSIZE) {
			coin_uname = name;
		} else {
			coin_uname = symbol;
		}
		coin_decimals = (uint8_t) msg->token.decimals;
		coin_type = msg->token.type;
    } else if (msg->coin.type == COIN_TYPE_CUSTOM_EVM) {
        name = msg->chain_info.name;
        symbol = msg->chain_info.native_symbol;
        coin_decimals = msg->chain_info.native_decimals;
        coin_type = msg->coin.type;
        coin_uname = msg->coin.uname;
		db_msg("COIN_TYPE_CUSTOM_EVM name:%s symbol:%s coin_uname:%s", name, symbol, coin_uname);
    } else {
        name = "Unkown Message";
    }

	if (!config && msg->coin.type) {
		config = getCoinConfigForMainType(msg->coin.type);
		if (!config) {
			db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
			return -1;
		}
	}

	if (trans_nft && coin_decimals != 0) {
		db_error("invalid trans_nft coin_decimals:%d", coin_decimals);
		coin_decimals = 0;
	}

	if (msg->sign_type == 1 || msg->sign_type == 2) {
		if (!strcmp(msg->contract.name, "Uniswap")) {
			coin_uname = "Uniswap";
		} else {
			coin_uname = "Dapp";
		}
		symbol = msg->contract.name;//show
		if (msg->sign_type == 1) {
			name = res_getLabel(LANG_LABEL_TX_METHOD_APPROVE);
		} else if (msg->sign_type == 2) {
			name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
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
//	view->coin_symbol = symbol;
	db_msg("name:%s symbol:%s coin_uname:%s msg->token.name:%s msg->token.symbol:%s", name, symbol, coin_uname, msg->token.name, msg->token.symbol);

	if (msg->sign_type == 0) { 
		double send_value = 0;
		view->total_height = 2 * SCREEN_HEIGHT;
		if (trans_nft) {
			view->coin_symbol = res_getLabel(LANG_LABEL_SEND_NFT);
			//view_add_txt(TXS_LABEL_NFT_ID_TITLE, "ID:");
			//view_add_txt(TXS_LABEL_NFT_AMOUNT_TITLE, res_getLabel(LANG_LABEL_ORDER_AMOUNT));
			view_add_txt(TXS_LABEL_NFT_ID_VALUE, msg->token.name);

			memset(tmpbuf, 0, sizeof(tmpbuf));
			if (is_transfer) {
				bignum_print(msg->data.bytes + 36, 32, coin_decimals, "", tmpbuf, sizeof(tmpbuf));
			} else if (is_transfer_from) {
				bignum_print(msg->data.bytes + 68, 32, coin_decimals, "", tmpbuf, sizeof(tmpbuf));
			} else if (is_1155_transfer) {
				bignum_print(msg->data.bytes + 68, 32, coin_decimals, "", tmpbuf, sizeof(tmpbuf));
			} else {
				tmpbuf[0] = '?';
				tmpbuf[1] = '?';
			}
			memset(disp, 0x0, sizeof(disp));
			snprintf(disp, sizeof(disp), "%s%s", "ID:", tmpbuf);
			view_add_txt(TXS_LABEL_NFT_ID_VALUE, disp);

			if (config) {
				view_add_txt(TXS_LABEL_NFT_ID_TITLE, "Chain:");
				view_add_txt(TXS_LABEL_NFT_ID_VALUE, config->name);
			}
		} else {
			view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
			ret = 0;
			db_msg("is_transfer:%d is_transfer_from:%d coin_decimals:%d", is_transfer, is_transfer_from, coin_decimals);
			if (is_transfer) {
				ret = bignum2double(msg->data.bytes + 36, 32, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
			} else if (is_transfer_from) {
				ret = bignum2double(msg->data.bytes + 68, 32, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
			} else if (msg->value.size > 0) {
				ret = bignum2double(msg->value.bytes, msg->value.size, coin_decimals, &send_value, tmpbuf, sizeof(tmpbuf));
			} else {
				tmpbuf[0] = 0;
			}
			if (ret != 0) {
				db_error("get send_value false ret:%d", ret);
				tmpbuf[0] = 0;
			}
			db_msg("get send_value:%.18lf str:%s", send_value, tmpbuf);
			view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
		    view_add_txt(TXS_LABEL_APP_MSG_VALUE, msg->token.symbol);
			
			view_add_txt(TXS_LABEL_NFT_ID_TITLE, "Chain:");
			if (msg->coin.type == COIN_TYPE_CUSTOM_EVM) {
				const char *temp_name = msg->chain_info.name;
				view_add_txt(TXS_LABEL_APP_MSG_VALUE, temp_name);
			} else {
				if (config) {
					view_add_txt(TXS_LABEL_NFT_ID_VALUE, config->name);
				}
			}
		}

		//from
		view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		if (is_1155_transfer || is_transfer_from) {
			tmpbuf[0] = '0';
			tmpbuf[1] = 'x';
			ethereum_address_checksum(msg->data.bytes + 16, tmpbuf + 2, false, 0);
		} else {
			if (is_not_empty_string(msg->coin.path)) {
                db_msg("msg->coin.path:%s", msg->coin.path);
                CoinPathInfo info;
                memzero(&info, sizeof(CoinPathInfo));
                if (parse_coin_path(&info, msg->coin.path) != 0 || info.hn < 3) {
                    db_error("invalid coin type:%d uname:%s path:%s", msg->coin.type, msg->coin.uname, msg->coin.path);
                    return -2;

                }

                db_msg("info.hn:%d,%d,%d", info.hn, info.hvalues[0], info.hvalues[info.hn - 1]);
                db_msg("info.an:%d,%d,%d", info.an, info.avalues[0], info.avalues[info.an - 1]);

                uint32_t index = 0;
                if (info.an == COIN_PATH_MAX_ANUM) {
                    index = info.avalues[info.an - 1];
                }
                ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, index, 0);
            } else {
                ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
            }
            db_msg("my address ret:%d addr:%s,ret:%d", ret, tmpbuf, ret);
		}
		view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

		//to
		view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tmpbuf[0] = '0';
		tmpbuf[1] = 'x';
		if (is_transfer) {
			ethereum_address_checksum(msg->data.bytes + 16, tmpbuf + 2, false, 0);
		} else if (is_1155_transfer || is_transfer_from) {
			ethereum_address_checksum(msg->data.bytes + 48, tmpbuf + 2, false, 0);
		} else if (msg->to.size > 0) {
			ethereum_address_checksum(msg->to.bytes, tmpbuf + 2, false, 0);
		} else {
			tmpbuf[0] = 0;
		}
		view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

		//fee
		view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
		if(msg->transaction_type == ETH_TRANSACTION_TYPE_1559){
			format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->eip1559GasFee.max_fee_per_gas*msg->gas_limit, 18);
			view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		}else{
			format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->gas_limit * msg->gas_price, 18);
			db_msg("feed value:%s", tmpbuf);
			view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		}

		if (msg->coin.type == COIN_TYPE_CUSTOM_EVM) {
			const char *native_symbol = msg->chain_info.native_symbol;
			view_add_txt(TXS_LABEL_APP_MSG_VALUE, native_symbol);
		} else {
			if (config) {
				view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);
			}
		}
		//data
		if (msg->data.size && !detected_data) {
			view->total_height += SCREEN_HEIGHT;
			view_add_txt(TXS_LABEL_DATA_TITLE, "Data:");
			format_data_to_hex(msg->data.bytes, msg->data.size, tmpbuf, sizeof(tmpbuf));
			view_add_txt(TXS_LABEL_DATA_CONTENT, tmpbuf);
		}
	} else if (msg->sign_type == 1) { //approval
		view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_APPROVE);;
		db->tx_type = TX_TYPE_APP_APPROVAL;
		
		view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
		view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

		if (config) {
			view_add_txt(TXS_LABEL_NFT_ID_TITLE, "Chain:");
			view_add_txt(TXS_LABEL_NFT_ID_VALUE, config->name);
		}

		snprintf(tmpbuf, sizeof(tmpbuf), "%s:", res_getLabel(LANG_LABEL_TX_LIMIT));
		view_add_txt(TXS_LABEL_APPROVE_AMOUNT_TITLE, tmpbuf);
		tmpbuf[0] = 0;
		if (buffer_is_ff(msg->data.bytes + 36, 32)) {
			view_add_txt(TXS_LABEL_APPROVE_AMOUNT_VALUE, res_getLabel(LANG_LABEL_TX_UNLIMITED));
		} else if (msg->token.type && msg->token.decimals >= 0) {
			double fee_value = 0;
			ret = bignum2double(msg->data.bytes + 36, 32, msg->token.decimals, &fee_value, tmpbuf, sizeof(tmpbuf));
			if (ret == 0) {
				view_add_txt(TXS_LABEL_APPROVE_AMOUNT_VALUE, tmpbuf);
			}
		}
		if (is_not_empty_string(msg->token.symbol)) {
            snprintf(tmpbuf, sizeof(tmpbuf), "%s", msg->token.symbol);
        } else if (is_not_empty_string(msg->token.name)) {
            snprintf(tmpbuf, sizeof(tmpbuf), "%s", msg->token.name);
        } else {
            tmpbuf[0] = '0';
            tmpbuf[1] = 'x';
            bin_to_hex(msg->to.bytes, 4, tmpbuf + 2);
            tmpbuf[10] = '.';
            tmpbuf[11] = '.';
            tmpbuf[12] = '.';
            bin_to_hex(msg->to.bytes + 16, 4, tmpbuf + 12);
        }
        view_add_txt(TXS_LABEL_APPROVE_TOKEN_VALUE, tmpbuf);
		
		// view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		// memset(tmpbuf, 0, sizeof(tmpbuf));
		// ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
		// db_msg("my address ret:%d addr:%s", ret, tmpbuf);
		// view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);


		// view_add_txt(TXS_LABEL_PAYTO_TITLE, "To");
		// memset(tmpbuf, 0, sizeof(tmpbuf));
		// tmpbuf[0] = '0';
		// tmpbuf[1] = 'x';
		// if (is_transfer) {
		// 	ethereum_address_checksum(msg->data.bytes + 16, tmpbuf + 2, false, 0);
		// } else if (is_1155_transfer || is_transfer_from) {
		// 	ethereum_address_checksum(msg->data.bytes + 48, tmpbuf + 2, false, 0);
		// } else if (msg->to.size > 0) {
		// 	ethereum_address_checksum(msg->to.bytes, tmpbuf + 2, false, 0);
		// } else {
		// 	tmpbuf[0] = 0;
		// }
		// view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);
		
		view_add_txt(TXS_LABEL_SIMPLE_FEE_TITLE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
		format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->gas_limit * msg->gas_price, 18);
		db_msg("feed value:%s", tmpbuf);
		view_add_txt(TXS_LABEL_SIMPLE_FEE_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);
		
	} else if (msg->sign_type == 2) { //app message
		view->coin_symbol = res_getLabel(LANG_LABEL_SIGN_TRANSACTION);
		
		view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
		view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

		if (config) {
			view_add_txt(TXS_LABEL_NFT_ID_TITLE, "Chain:");
			view_add_txt(TXS_LABEL_NFT_ID_VALUE, config->name);
		}
		
		// view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		// memset(tmpbuf, 0, sizeof(tmpbuf));
		// ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
		// db_msg("my address ret:%d addr:%s", ret, tmpbuf);
		// view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);


	    view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tmpbuf[0] = '0';
		tmpbuf[1] = 'x';
		if (is_transfer) {
			ethereum_address_checksum(msg->data.bytes + 16, tmpbuf + 2, false, 0);
		} else if (is_1155_transfer || is_transfer_from) {
			ethereum_address_checksum(msg->data.bytes + 48, tmpbuf + 2, false, 0);
		} else if (msg->to.size > 0) {
			ethereum_address_checksum(msg->to.bytes, tmpbuf + 2, false, 0);
		} else {
			tmpbuf[0] = 0;
		}
		view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);
		
		view->flag |= 0x1;
		//fee
		view_add_txt(TXS_LABEL_SIMPLE_FEE_TITLE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
		format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->gas_limit * msg->gas_price, 18);
		db_msg("feed value:%s", tmpbuf);
		view_add_txt(TXS_LABEL_SIMPLE_FEE_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);

		view_add_txt(TXS_LABEL_APP_MSG_VALUE, "Data:");
		db->tx_type = TX_TYPE_APP_SIGN_MSG;
		format_data_to_hex(msg->data.bytes, msg->data.size, tmpbuf, 50);
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, tmpbuf);
	}
	

	//save coin info
	if (trans_token && coin_type && view->msg_from == MSG_FROM_QR_APP) {
		if (!storage_isCoinExist(coin_type, coin_uname)) {
			// if (config) {
			// 	storage_save_coin_info(config);
			// }  
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

