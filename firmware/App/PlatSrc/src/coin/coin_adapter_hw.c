#include "coin_adapter_hw.h"
#include "cdr.h"
#include "wallet_adapter.h"
#include "cdr_widgets.h"

BatchSignCollector gBatchSignCollector = {0};

int tx_common_show_sign_result(HWND hwnd, const ProtoClientMessage *msg, struct pbc_wmessage *sigmsg, int msgtype) {
	struct pbc_slice slice;
	int ret = 0;
	pbc_wmessage_buffer(sigmsg, &slice);
	//db_msg("result sz:%d data:%s", slice.len, debug_bin_to_hex((const char *) slice.buffer, slice.len));

	if (gBatchSignCollector.active) {
		// Batch mode: capture the result, do not display QR. BatchSignWin will
		// pack all collected results into a single response QR.
		gBatchSignCollector.data = (unsigned char *) malloc(slice.len);
		if (!gBatchSignCollector.data) {
			db_error("batch collector malloc %d false", (int) slice.len);
			proto_delete_wmessage(sigmsg);
			return -1;
		}
		memcpy(gBatchSignCollector.data, slice.buffer, slice.len);
		gBatchSignCollector.size = (int) slice.len;
		gBatchSignCollector.msg_type = (uint16_t) msgtype;
		gBatchSignCollector.flag = msg->flag;
		gBatchSignCollector.client_id = msg->client_id;
		proto_delete_wmessage(sigmsg);
		return 0;
	}

	ret = showQRWindow(hwnd, msg->client_id, msg->flag, msgtype, (const unsigned char *) slice.buffer, (int) slice.len);
	if (ret < 0) {
		db_error("show msg:%d false,ret:%d", msgtype, ret);
	}

	proto_delete_wmessage(sigmsg);
	return ret;
}

void tx_set_db_view(const CoinConfig *config, DBTxCoinInfo *db, DynamicViewCtx *view) {
	db->coin_type = config->type;
	strlcpy(db->coin_name, config->name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, config->symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, config->uname, sizeof(db->coin_uname));

	view->coin_type = config->type;
	view->coin_uname = config->uname;
	view->coin_name = config->name;
	view->coin_symbol = config->symbol;
}

void tx_set_db_view_info(DBTxCoinInfo *db, DynamicViewCtx *view, int coin_type, const char *coin_uname, const char *coin_name, const char *coin_symbol) {
	db->coin_type = coin_type;
	strlcpy(db->coin_name, coin_name, sizeof(db->coin_name));
	strlcpy(db->coin_symbol, coin_symbol, sizeof(db->coin_symbol));
	strlcpy(db->coin_uname, coin_uname, sizeof(db->coin_uname));

	view->coin_type = coin_type;
	view->coin_uname = coin_uname;
	view->coin_name = coin_name;
	view->coin_symbol = coin_symbol;
}
