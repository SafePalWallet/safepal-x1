#ifdef COIN_SIGN_VIEW_FILE

#ifdef VIEW_CODE_IN_IDE

#include "coin/Kaspa/kaspa_sign.c"
#include "coin/Kaspa/kaspa_proto.c"

#endif

#include "dynamic_win.h"
#include "storage_manager.h"
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
    char tmpbuf[128];
    coin_state *s = (coin_state *) session;
    if (!s) {
        db_error("invalid session");
        return -1;
    }

    KaspaSignRequest *msg = &s->req;
    DBTxCoinInfo *db = &view->db;

    memset(db, 0, sizeof(DBTxCoinInfo));
    if (proto_check_exchange(&msg->exchange) != 0) {
        db_error("invalid exchange");
        return -102;
    }
    int ret = 0;
    const CoinConfig *coinConfig = getCoinConfig(COIN_TYPE_KASPA, "KAS");
    if (NULL == coinConfig) {
        db_error("not support type:%d name:%s", msg->coin.type, msg->coin.uname);
        return -181;
    }

    if (msg->coin.type == COIN_TYPE_KASPA) {
        storage_save_coin_info(coinConfig);
    }

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
            if (msg->outputs[i].flag & 0x01) {
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
    int first_output_offset = SCREEN_HEIGHT; // res_getInt(MK_txs_sign, "first_output_offset", 0);
    int output_item_height = 105;             // res_getInt(MK_txs_sign, "output_item_height", 0);
    if (!output_item_height)
        output_item_height = mScreenHeight;

    int num_perpage = mScreenHeight / output_item_height;

    // move ok to right pos
    int total_height = first_output_offset + mScreenHeight * ((out_item_count + num_perpage - 1) / num_perpage);

    db_msg("first_output_offset:%d output_item_height:%d out_item_count:%d total_height:%d num_perpage:%d",
           first_output_offset, output_item_height, out_item_count, total_height, num_perpage);
    view->has_more = 1;
    view->total_height = total_height;
    view->coin_symbol = res_getLabel(LANG_LABEL_SEND);
    db->coin_type = msg->coin.type;
    strlcpy(db->coin_name, coinConfig->name, sizeof(db->coin_name));
    strlcpy(db->coin_symbol, coinConfig->symbol, sizeof(db->coin_symbol));
    strlcpy(db->coin_uname, coinConfig->uname, sizeof(db->coin_uname));

    view->coin_type = msg->coin.type;
    view->coin_uname = coinConfig->uname;
    view->coin_name = coinConfig->name;

    format_coin_real_value(tmpbuf, sizeof(tmpbuf), send_value, coin_decimals);
    view_add_txt(0, tmpbuf);
    view_add_txt(0, coinConfig->symbol);

    int item_index = 0;
    for (int i = 0; i < msg->output_n; i++) {
        if (!(msg->outputs[i].flag & 0x01)) {
            if (out_item_count > 1) {
                snprintf(tmpbuf, sizeof(tmpbuf), res_getLabel(LANG_LABEL_TXS_PAYTO_INDEX), item_index + 1);
            } else {
                strlcpy(tmpbuf, res_getLabel(LANG_LABEL_TXS_PAYTO_TITLE), sizeof(tmpbuf));
            }
            view_add_txt(0, tmpbuf);
            view_add_txt(0, msg->outputs[i].address);
            format_coin_real_value(tmpbuf, sizeof(tmpbuf), msg->outputs[i].value, coin_decimals);
            view_add_txt(0, tmpbuf);

            view_add_txt(0, coinConfig->symbol);
            item_index++;
        }
    }

    view_add_txt(0, res_getLabel(LANG_LABEL_TXS_FEED_TITLE));
    format_coin_real_value(tmpbuf, sizeof(tmpbuf), feed_value, coin_decimals);
    view_add_txt(0, tmpbuf);
    view_add_txt(0, coinConfig->symbol);

    item_index = 0;
    if (msg->input_n > 0) {
        for (int i = 0; i < msg->input_n; i++) {
            if (msg->input_n > 1) {
                snprintf(tmpbuf, sizeof(tmpbuf), res_getLabel(LANG_LABEL_TXS_FROM_INDEX), item_index + 1);
            } else {
                strlcpy(tmpbuf, res_getLabel(LANG_LABEL_TXS_FROM_TITLE), sizeof(tmpbuf));
            }
            view_add_txt(0, tmpbuf);
            view_add_txt(0, msg->inputs[i].address);
            item_index++;
        }
    }

    int change_count = 0;
    for (int i = 0; i < msg->output_n; i++) {
        if (msg->outputs[i].flag & 0x01) {
            change_count++;
        }
    }

    if (change_count > 0) {
        for (int i = 0; i < msg->output_n; i++) {
            if (!(msg->outputs[i].flag & 0x01))
                continue;

            view_add_txt(0, res_getLabel(LANG_LABEL_TXS_CHANGE_TITLE));
            view_add_txt(0, msg->outputs[i].address);
        }
    }

    if (view->msg_from == MSG_FROM_QR_APP) {
        if (!storage_isCoinExist(db->coin_type, db->coin_uname)) {
            DBCoinInfo dbinfo;
            memset(&dbinfo, 0, sizeof(dbinfo));
            dbinfo.type = (uint8_t) db->coin_type;
            dbinfo.curv = coin_get_curv_id(db->coin_type, db->coin_uname);
            dbinfo.decimals = coin_decimals;
            strncpy(dbinfo.uname, db->coin_uname, COIN_UNAME_MAX_LEN);
            strncpy(dbinfo.name, db->coin_name, COIN_NAME_MAX_LEN);
            strncpy(dbinfo.symbol, db->coin_symbol, COIN_SYMBOL_MAX_LEN);
            storage_save_coin_dbinfo(&dbinfo);
        }
    }
    return 0;
}

#endif