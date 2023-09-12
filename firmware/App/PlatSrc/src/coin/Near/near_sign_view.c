#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include <coin/Near/near_proto.h>
#include "coin/Near/near_sign.c"

#endif

#include "coin_util_hw.h"

#define NEAR_FEE_DEC 24

enum {
    TXS_LABEL_TOTAL_VALUE,
    TXS_LABEL_TOTAL_MONEY,
    TXS_LABEL_FEED_TILE,
    TXS_LABEL_FEED_VALUE,
    TXS_LABEL_PAYFROM_TITLE,
    TXS_LABEL_PAYFROM_ADDRESS,
    TXS_LABEL_PAYTO_TITLE,
    TXS_LABEL_PAYTO_ADDRESS,
    TXS_LABEL_APP_MSG_VALUE,
    TXS_LABEL_MAXID,
};

static int on_sign_show(void *session, DynamicViewCtx *view) {
	char tmpbuf[128], buf[128];
    int coin_type = 0;
    const char *coin_uname = NULL;
    const char *name = NULL;
    const char *symbol = NULL;
    double send_value = 0;
    int value = 0;
    int ret;
    uint8_t coin_decimals = 0;
    const CoinConfig *config = NULL;
    int fee_dec = 24;

    coin_state *s = (coin_state *) session;
    if (!s) {
        db_error("invalid session");
        return -1;
    }

    NearSignTxReq *msg = &s->req;
    DBTxCoinInfo *db = &view->db;
    memset(db, 0, sizeof(DBTxCoinInfo));

#if 1
    db_msg("-------------------------------");
    db_msg("msg->coin.type:%x", (int) msg->coin.type);
    db_msg("msg->coin.uname:%s", msg->coin.uname);
    db_msg("msg->coin.path:%s", msg->coin.path);

    db_msg("msg->exchange.amount:%d", (int) msg->exchange.amount);
    db_msg("msg->exchange.currency:%s", msg->exchange.currency);
    db_msg("msg->exchange.symbol:%s", msg->exchange.symbol);
    db_msg("msg->exchange.value:%lld", msg->exchange.value);

    db_msg("msg->operation_type:%d", msg->operation_type);

    if ((char) msg->operation_type == REGISTER_PUBKEY) {
        db_msg("msg->action.regKey.hash:%s", msg->action.regKey.hash);
        db_msg("msg->action.regKey.blockHash:%s", msg->action.regKey.blockHash);
        db_msg("msg->action.regKey.nonce:%s", msg->action.regKey.nonce);
    } else if ((char) msg->operation_type == TRANSFER) {
        db_msg("msg->action.sendCoins.from_address:%s", msg->action.sendCoins.from_address);
        db_msg("msg->action.sendCoins.to_address:%s", msg->action.sendCoins.to_address);
        db_msg("msg->action.sendCoins.nonce:%s", msg->action.sendCoins.nonce);
        db_msg("msg->action.sendCoins.txHash:%s", msg->action.sendCoins.txHash);
        db_msg("msg->action.sendCoins.blockHash:%s", msg->action.sendCoins.blockHash);
    } else if ((char) msg->operation_type == DAPP) {
        db_msg("msg->action.dapp.app_name:%s", msg->action.dapp.app_name);
        db_msg("msg->action.dapp.hash:%s", msg->action.dapp.hash);
        db_msg("msg->action.dapp.message:%s", msg->action.dapp.message);
    } else if ((char) msg->operation_type == NFT) {
        db_msg("msg->action.nft.tokenId:%s", msg->action.nft.tokenId);
        db_msg("msg->action.nft.hash:%s", msg->action.nft.hash);
        db_msg("msg->action.nft.to_address:%s", msg->action.nft.to_address);
    }
    db_msg("--------------------------------");
#endif

    coin_type = msg->coin.type;
    if (is_empty_string(msg->coin.uname)) {
        db_error("invalid uname");
        return -2;
    }
    coin_uname = msg->coin.uname;

    config = getCoinConfig(msg->coin.type, msg->coin.uname);
	if (!config) {
		config = getCoinConfig(msg->coin.type, "NEAR");
	}

    if ((char) msg->operation_type == REGISTER_PUBKEY) {
        name = msg->action.regKey.app_name;
        symbol = msg->action.regKey.app_name;
    } else if ((char) msg->operation_type == TRANSFER) {
        if (strcmp(msg->coin.uname, "NEAR") == 0) {
            db_msg("not config type:%d name:%s", msg->coin.type, msg->coin.uname);
            name = msg->coin.uname;
            symbol = msg->coin.uname;
            coin_decimals = 24;
        } else {//token
            if (is_empty_string(msg->token.name) || is_empty_string(msg->token.symbol)) {
                db_error("invalid dtoken name:%s or symbol:%s", msg->token.name, msg->token.symbol);
                return -3;
            }
            name = msg->token.name;
            symbol = msg->token.symbol;
            coin_decimals = msg->token.decimals;
        }
    } else if ((char) msg->operation_type == DAPP) {
        name = res_getLabel(LANG_LABEL_TX_METHOD_SIGN_MSG);
        symbol = msg->action.dapp.app_name;
    } else if ((char) msg->operation_type == NFT) {
        name = msg->action.nft.app_name;
        symbol = msg->action.nft.app_name;
        db->flag |= FLAG_NFT;
    }

    if ((char) msg->operation_type == REGISTER_PUBKEY) {
		view->coin_symbol = res_getLabel(LANG_LABEL_TX_METHOD_LOGIN);
        db->tx_type = TX_TYPE_APP_APPROVAL;
        //contract_id
        view_add_txt(TXS_LABEL_TOTAL_VALUE, "contract_id");
        view_add_txt(TXS_LABEL_TOTAL_MONEY, msg->action.regKey.contractId);

        //public key
        view_add_txt(TXS_LABEL_PAYFROM_TITLE, "public key");
        memset(buf, 0x0, sizeof(buf));
        omit_string(tmpbuf, msg->action.regKey.pubkey, 26, 11);
        view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

       //fee
        memset(tmpbuf, 0x00, sizeof(tmpbuf));
        ret = bignum2double((const unsigned char *) msg->action.regKey.fee.bytes,
                            msg->action.regKey.fee.size, NEAR_FEE_DEC, NULL, tmpbuf,
                            sizeof(tmpbuf));
        db_msg("bignum2double ret:%d,tmpbuf:%s", ret, tmpbuf);
        view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);
    } else if ((char) msg->operation_type == TRANSFER) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
        if (proto_check_exchange(&msg->exchange) != 0) {
            db_error("invalid exchange");
            return -4;
        }

        double ex_rate = proto_get_exchange_rate_value(&msg->exchange);
        const char *money_symbol = proto_get_money_symbol(&msg->exchange);
        strlcpy(db->currency_symbol, money_symbol, sizeof(db->currency_symbol));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        db_msg("coin_decimals:%d", coin_decimals);
        ret = bignum2double((const unsigned char *) msg->action.sendCoins.amount.bytes,
                            msg->action.sendCoins.amount.size, coin_decimals, &send_value, tmpbuf,
                            sizeof(tmpbuf));
        db_msg("bignum2double ret:%d,send_value:%f,tmpbuf:%s", ret, send_value, tmpbuf);
        strlcpy(db->send_value, tmpbuf, sizeof(db->send_value));
        view_add_txt(TXS_LABEL_TOTAL_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, msg->token.symbol);

        view_add_txt(TXS_LABEL_MAXID, "Chain:");
		view_add_txt(TXS_LABEL_MAXID, config->name);

        view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.sendCoins.from_address, 26, 11);
        view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

        view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.sendCoins.to_address, 26, 11);
        view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

        view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        db_msg("coin_decimals:%d", coin_decimals);
        ret = bignum2double((const unsigned char *) msg->action.sendCoins.fee.bytes,
                            msg->action.sendCoins.fee.size, NEAR_FEE_DEC, NULL, tmpbuf,
                            sizeof(tmpbuf));
        view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
		view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);
    } else if ((char) msg->operation_type == DAPP) {
        db->tx_type = TX_TYPE_APP_SIGN_MSG;
		view->coin_symbol = res_getLabel(LANG_LABEL_SIGN_TRANSACTION);

        //dapp
		view_add_txt(TXS_LABEL_TOTAL_VALUE, "DApp:");
		view_add_txt(TXS_LABEL_TOTAL_MONEY, symbol);

        view_add_txt(TXS_LABEL_MAXID, "Chain:");
		view_add_txt(TXS_LABEL_MAXID, config->name);

        //from
		view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
		memset(tmpbuf, 0, sizeof(tmpbuf));
		ret = wallet_gen_address(tmpbuf, sizeof(tmpbuf), NULL, coin_type, coin_uname, 0, 0);
		db_msg("my address ret:%d addr:%s", ret, tmpbuf);
		view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

        //fee
        view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        if (msg->action.dapp.isSmallFee) {
            snprintf(tmpbuf, sizeof(tmpbuf), "< %s", "0.00001");
        } else {
            bignum2double((const unsigned char *) msg->action.dapp.fee.bytes,
                          msg->action.dapp.fee.size, NEAR_FEE_DEC, NULL, tmpbuf,
                          sizeof(tmpbuf));
        }
        view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
        view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);

        //data
        view_add_txt(TXS_LABEL_APP_MSG_VALUE, "Data:");
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.dapp.message, 52, 20);
        view_add_txt(TXS_LABEL_APP_MSG_VALUE, tmpbuf);
    } else if ((char) msg->operation_type == NFT) {
		view->coin_symbol = res_getLabel(LANG_LABEL_SEND_NFT);

        //token id
        view_add_txt(TXS_LABEL_TOTAL_VALUE, "Token ID");
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        snprintf(tmpbuf, sizeof(tmpbuf), "#%s", msg->action.nft.tokenId);
        view_add_txt(TXS_LABEL_TOTAL_MONEY, tmpbuf);

        view_add_txt(TXS_LABEL_MAXID, "Chain:");
		view_add_txt(TXS_LABEL_MAXID, config->name);

        //addr
        view_add_txt(TXS_LABEL_PAYFROM_TITLE, res_getLabel(LANG_LABEL_TXS_PAYFROM_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.nft.from_address, 26, 11);
        view_add_txt(TXS_LABEL_PAYFROM_ADDRESS, tmpbuf);

        view_add_txt(TXS_LABEL_PAYTO_TITLE, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        omit_string(tmpbuf, msg->action.nft.to_address, 26, 11);
        view_add_txt(TXS_LABEL_PAYTO_ADDRESS, tmpbuf);

        //fee
        view_add_txt(TXS_LABEL_FEED_TILE, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
        memset(tmpbuf, 0x0, sizeof(tmpbuf));
        bignum2double((const unsigned char *) msg->action.nft.fee.bytes,
                      msg->action.nft.fee.size, NEAR_FEE_DEC, NULL, tmpbuf,
                      sizeof(tmpbuf));
        view_add_txt(TXS_LABEL_FEED_VALUE, tmpbuf);
        view_add_txt(TXS_LABEL_APP_MSG_VALUE, config->symbol);
    }
    view->total_height = 2 * SCREEN_HEIGHT;

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
