#define LOG_TAG "showQRWindow"

#include "common_c.h"
#include "resource.h"
#include "cstr.h"
#include "qr_pack.h"
#include "cdr_widgets.h"
#include "storage_manager.h"
#include "wallet_proto.h"
#include "common_util.h"
#include "cdr_widgets.h"
#include "gui_api.h"
#include "BtProcWin.h"

int showQRWinProc(qr_packet_chunk_info *chunk_result) {
    //db_msg("chunk_result->total:%d",chunk_result->total);
    int total = chunk_result->total;
    int ret = -1;

    if (!chunk_result || !chunk_result->chunks) {
        return -1;
    }

    for (int index = 0; index < total; index++) {
        if (is_printable_str((const char *) chunk_result->chunks[index].data)) {
            //db_verbose("index:%d str qr:%d=>%s", index, chunk_result->chunks[index].size, chunk_result->chunks[index].data);
        } else {
            //db_verbose("index:%d bin qr:%d=>%s", index, chunk_result->chunks[index].size,
            // debug_ubin_to_hex(chunk_result->chunks[index].data, chunk_result->chunks[index].size));
        }

        //db_msg("ble data:%s", debug_bin_to_hex(chunk_result->chunks[index].data, chunk_result->chunks[index].size));
        ret = ddi_bt_write(chunk_result->chunks[index].data, chunk_result->chunks[index].size);
        if (ret != chunk_result->chunks[index].size) {
            db_error("ddi_bt_write error ret:%d,datasize:%d,index:%d", ret, chunk_result->chunks[index].size, index);
            ret = PROC_ERROR_BLE_SEND_DATA;
            break;
        }

        ddi_sys_msleep(30);
    }

    return ret;
}

int showQRWindow(HWND hParent, int client_id, unsigned int flag, int msgtype, const unsigned char *qrdata, int size) {
    qr_packet_chunk_info packet_chunk_info;
    CDR_RECT win_rect;
    CDR_RECT ind_rect;
    int ret;
    int show_raw = (flag & SHOW_QR_FLAG_RAW_DATA) ? 1 : 0;
    int aes_encode = client_id > 0 ? 1 : 0;
    unsigned char seckey[CLIENT_SECKEY_SIZE] = {0};
    qr_packet_chunk_slice singal_chunk_slice;
    qr_packet_chunk_info *chunk_info = &packet_chunk_info;

    int qrtype = QR_TYPE_BIN;
    if (client_id > 0 && aes_encode) {
        if (storage_getClientSeckey(client_id, seckey) <= 0) {
            db_error("get client:%d seckey false", client_id);
            return -1;
        } else {
            db_msg("qr client_id:%d, seckey:%s", client_id, debug_bin_to_hex(seckey, sizeof(seckey)));
        }
    }

    int max_chunk_size = 180;//res_getInt(MK_qr_window, "chunk_size", 194);
    if (Global_Ble_Mtu >= 10 && Global_Ble_Mtu <= 512) {
        max_chunk_size = MIN(180, Global_Ble_Mtu - 3);
    }
    if (aes_encode == 1 && msgtype == QR_MSG_MESSAGE_SIGN_RESP) {//add for iphone13
        max_chunk_size = 58;
    }
    //db_msg("max_chunk_size=%d,qrtype=%d,show_raw=%d,aes_encode=%d",max_chunk_size,qrtype,show_raw,aes_encode);
    if (max_chunk_size < 34) {
        max_chunk_size = 34;
    } else if (max_chunk_size > 461) {
        max_chunk_size = 461;
    }
    if (max_chunk_size == 194 && qrtype == QR_TYPE_BIN) { //Try to display it on one page
        int one_page_size = size + QRCODE_PREFIX_LEN + get_qr_packet_header_len(0); // == 14
        if (one_page_size > 194 && one_page_size <= 220) {
            max_chunk_size = 220;
        }
    }
    if (show_raw) {
        chunk_info->total = 1;
        singal_chunk_slice.data = (unsigned char *) qrdata;
        singal_chunk_slice.size = size;
        chunk_info->chunks = &singal_chunk_slice;
        ret = 0;
    } else {
        ret = split_qr_packet(chunk_info, qrdata, size, qrtype, msgtype, aes_encode ? QR_FLAG_CRYPT_AES : 0, client_id,
                              seckey, max_chunk_size);
    }

    if (ret != 0) {
        db_error("split_qr_packet false ret:%d", ret);
        return -1;
    }

    int sst = set_temp_screen_time(180);//screenon
    ret = showQRWinProc(chunk_info);
    if (ret >= 0) {
        ret = 0;
    }
    set_temp_screen_time(sst);
    if (!show_raw) {
        free_qr_packet_chunk(chunk_info);
    }
    //db_debug("end show qr ret:%d", ret);
    return ret;
}
