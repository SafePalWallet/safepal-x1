#define LOG_TAG "BtRecvCode"

#include "qr_pack.h"
#include "wallet_proto.h"
#include "global.h"
#include "cdr.h"
#include "ex_types.h"
#include "debug.h"
#include "cdrLang.h"
#include "wallet_proto_qr.h"
#include "device.h"
#include "wallet_util_hw.h"
#include "BtProcWin.h"
#include "storage_manager.h"
#include "BtRecvCode.h"
#include "gui_api.h"
#include "resource.h"
#include "libddi.h"
#include "key_event.h"

static bool mQrEnable = false;
static cstring *mLastQrResult = NULL;
static qr_packet mQrResult;
static qr_packet_buffer mQrBuffer;

int clearBtDecode(int type) {
    db_msg("type:%d", type);
    if (mLastQrResult != NULL) {
        cstr_free(mLastQrResult);
        mLastQrResult = NULL;
    }
    if (type == 0) {
        free_qr_packet(&mQrResult);
    }
    free_qr_buffer(&mQrBuffer);
    return 0;
}

int onBtParseQr(int type, qr_packet *packet) {
    /*if (mCurWindowID != WINDOWID_SCAN) {
        db_error("error winid:%d", mCurWindowID);
        return -1;
    }*/
    if (!packet->data) {
        db_error("type:%d not data", type);
        return -1;
    }

    ProtoClientMessage *msg = proto_decode_client_message(packet);
    if (!msg) {
        db_error("decode qr false type:%d", type);
        //sendMessage(WINDOWID_QRPROC, MSG_QR_ERROR, packet->type ? QR_DECODE_UNSUPPORT_MSG : QR_DECODE_INVALID_MSG, 0);
        //xchangeWindow(WINDOWID_QRPROC);
        return packet->type ? QR_DECODE_UNSUPPORT_MSG : QR_DECODE_INVALID_MSG;
    }
    //invalid account
    if (msg->account_id && gSeedAccountId && msg->account_id != ((uint32_t) gSeedAccountId)) {
        db_error("invalid account msg type:%d account:%x seed account:%llx ", msg->type, msg->account_id,
                 gSeedAccountId);
        //sendMessage(WINDOWID_QRPROC, MSG_QR_ERROR, QR_DECODE_ACCOUNT_MISMATCH, msg->type);
        proto_client_message_delete(msg);
        //xchangeWindow(WINDOWID_QRPROC);
        return QR_DECODE_ACCOUNT_MISMATCH;
    }

    int invalid = 1;
    int winid = 0;
    do {
        if (!msg->type) {
            db_error("empty type");
            break;
        }
        if ((!gHaveSeed && msg->type < QR_MSG_BLE_DEVICE_ACTIVE_REQUEST) || (gHaveSeed && msg->type > QR_MSG_INIT_BASE)) {
            db_serr("invalid state qr type:%d seed:%d", type, gHaveSeed);
            break;
        }
        if (msg->type == QR_MSG_BLE_DEVICE_ACTIVE_REQUEST && device_get_active_time() > 0) {
            db_serr("device actived,skip...");
            break;
        }
        winid = get_message_process_winid(msg);
        if (!winid) {
            db_serr("invalid msg type:%d", msg->type);
            break;
        }
        invalid = 0;
    } while (0);

    if (invalid) {
        proto_client_message_delete(msg);
        return -1;
    }
    db_msg("send qr result type:%d client:%d -> win:%d", msg->type, msg->client_id, winid);
    //sendMessage(winid, MSG_QR_RESULT, msg->type, (LPARAM) msg);
    //xchangeWindow(winid);

    btProcInit(msg);

    return winid;
}

int onBtResult(const char *data, int size) {
    int finish = 0;
    int errcode = 0;
    int win = 0;

    /*
    device_set_last_active_time(getClockTime());*/
    if (!mQrEnable) {
        db_debug("not qr enable");
        return -1;
    }
    if (mLastQrResult != NULL) {
        if ((int) mLastQrResult->len == size && memcmp(mLastQrResult->str, data, size) == 0) {
            db_debug("skip same qr rs:%p", mLastQrResult);
            return 2;
        } else {
            //db_debug("diff qr:%p old len:%d new sz:%d", mLastQrResult, mLastQrResult->len, size);
        }
    }
    if (mLastQrResult != NULL) {
        cstr_set_buf(mLastQrResult, data, size);
    } else {
        mLastQrResult = cstr_new_buf(data, size);
    }
    //db_debug("last qr:%p sz:%d str_p:%p", mLastQrResult, mLastQrResult->len, mLastQrResult->str);

    qr_packet *qr = &mQrResult;
    if (is_bin_qr_packet(data, size)) {
        errcode = merge_qr_packet_buffer(&mQrBuffer, qr, data, (size_t) size);
        if (errcode == 0) {
            finish = 1;
        } else if (errcode == 1) {
            errcode = 0;
        }
    } else {
        db_debug("qr not isBinPacket");
        if (qr->p_total > 1) {
            db_error("not multi qrcode");
            errcode = -201;
        } else {
            finish = 1;
            free_qr_packet(qr);
            qr->p_total = 1;
            qr->data = cstr_new_buf(data, size);
        }
    }
    if (errcode == QR_DECODE_SUCCESS && finish) { //decode
        if (qr->client_id) {
            unsigned char aes256key[32];

            if (storage_getClientSeckey(qr->client_id, aes256key) > 0) {
                db_debug("client:%d aes256key:%s", qr->client_id, debug_ubin_to_hex(aes256key, 32));
                if (decrypt_qr_packet(qr, aes256key) != 0) {
                    db_error("aes decrypt qr packet false");
                    errcode = QR_DECODE_PACKET_FAILED;
                }
            } else {
                db_error("get client_id:%d seckey false", qr->client_id);
                errcode = QR_DECODE_ACCOUNT_MISMATCH;//QR_DECODE_UNKOWN_CLIENT;
            }
        }
        if (errcode == QR_DECODE_SUCCESS && verify_qr_packet(qr) != 0) {
            db_error("check packet hash false");
            errcode = QR_DECODE_INVALID_HASH_CHECK;
        }
    }
    if (errcode == QR_DECODE_SUCCESS) {
        if (finish) {
            db_msg("type:%d total:%d index:%d len:%d", qr->type, qr->p_total, qr->p_index, qr->data->len);
            BtRecvDeinit();
            win = onBtParseQr(qr->type, qr);
            if (win == WINDOWID_QRPROC) {
                db_msg("onBtParseQr success");
                return WINDOWID_QRPROC;
            } else if (win == WINDOWID_TXSHOW) {
                db_msg("onBtParseQr success to sig");
                return WINDOWID_TXSHOW;
            } else if (win == QR_DECODE_ACCOUNT_MISMATCH || win == QR_DECODE_UNSUPPORT_MSG || win == QR_DECODE_INVALID_MSG) {
                db_msg("invalid win:%d", win);
                return win;
            } else {
                return -3;
            }
        } else if (qr->p_total >= 1) {
            if ((qr->p_index + 1) == qr->p_total) {
                //stopPreviewNoLock();
                BtRecvDeinit();
            }
            //mAppMain->sendUiEvent(UI_EVENT_QR_CHUNK, qr->p_index, qr->p_total);
            return QR_GET_MULTI_PACKETS;
        }
    } else {
        //stopPreviewNoLock();
        //mAppMain->sendUiEvent(UI_EVENT_QR_ERROR, errcode);
        BtRecvDeinit();
        return errcode;
    }

    BtRecvDeinit();

    return -4;
}

int setBtDecode(bool enable) {
    mQrEnable = enable;
    return 0;
}

void BtRecvInit(void) {
    init_qr_packet(&mQrResult, 0);
    clearBtDecode(0);
    setBtDecode(true);
}

void BtRecvDeinit(void) {
    setBtDecode(false);
    clearBtDecode(1);
}

static int bt_read_(unsigned char *buff, uint32_t datalen) {
    uint32_t begin_tick = 0;
    uint32_t end_tick = 0;
    int recvLen = 0;
    int tmplen;
    ddi_sys_get_tick(&begin_tick);
    do {
        tmplen = ddi_bt_read(buff + recvLen, datalen - recvLen);
        if (tmplen < 0) {
            db_error("bt recv header tmplen error:%d recvLen:%d", tmplen, recvLen);
            if (!recvLen) recvLen = tmplen;
            break;
        }
        if (tmplen) {
            recvLen += tmplen;
            ddi_sys_get_tick(&begin_tick);
        } else {
            ddi_sys_get_tick(&end_tick);
            if (get_diff_tick(end_tick, begin_tick) >= 2000) {
                db_error("bt recv is timeout");
                return -2;
            }
            // bt_read is not block API,not update begin_tick
            //begin_tick = end_tick;
        }
    } while (recvLen < datalen);
    return recvLen;
}

int onBtRecvData(uint8_t *recvBuff, uint32_t bufLen) {
    uint8_t head[QRCODE_PREFIX_LEN + QR_PACKET_HEADER_LEN] = {0};
    int recvLen = 0;
    int find = 0;
    int datalen;
    if (!recvBuff) {
        db_msg("recvBuff is null");
        return -1;
    }

    do { //temp use find value
        recvLen = ddi_bt_read(head + find, QRCODE_PREFIX_LEN - find);
        if (recvLen <= 0 || recvLen > 2) { //error or not read
            return 0;
        }
        find += recvLen;
        if (find == 1) {
            head[1] = 0;
            if (head[0] == 'B' || head[0] == 'C') {
                continue; //try again
            }
            head[0] = 0;
            find = 0;//clear all
        } else if (find == 2) {
            if (head[1] == ':' && (head[0] == 'B' || head[0] == 'C')) {
                break;
            } else if (head[1] == 'B' || head[1] == 'C') {
                head[0] = head[1];
                head[1] = 0;
                find = 1;
            } else {
                head[0] = 0;
                head[1] = 0;
                find = 0;
            }
        } else { //error??
            return 0;
        }
    } while (1);

    if (memcmp(head, "C:", 2) == 0) {
        recvLen = bt_read_(head + QRCODE_PREFIX_LEN, 2); //read datalen
        if (recvLen != 2) {
            db_error("read header failed ret:%d", recvLen);
            return -1;
        }
        datalen = ((*(head + 2)) << 8) | ((*(head + 3)) << 0);
        db_msg("C: len:%d bufLen:%d", datalen, bufLen);
        if (datalen > bufLen) {
            return -11;
        }
        recvLen = bt_read_(recvBuff, datalen);
        if (recvLen != datalen) {
            db_error("C: len:%d recvLen:%d", recvLen);
            return -12;
        }
        return KEY_EVENT_ABORT;
    }

    recvLen = bt_read_(head + QRCODE_PREFIX_LEN, QR_PACKET_HEADER_LEN);
    if (recvLen != QR_PACKET_HEADER_LEN) {
        db_error("read header failed ret:%d", recvLen);
        return -1;
    }
    datalen = qr_packet_get_len(head, sizeof(head));
    db_msg("datalen:%d", datalen);
    if (datalen > (bufLen - sizeof(head)) || datalen < 0) {
        db_error("error, recvLen:%d, head:%s", recvLen, debug_ubin_to_hex(head, 12));
        return -3;
    }
    memcpy(recvBuff, head, sizeof(head));
    recvLen = bt_read_(recvBuff + sizeof(head), datalen);
    if (recvLen != datalen) {
        db_error("error, recvLen:%d, datalen:%d", recvLen, datalen);
        return -4;
    }
    return (int) sizeof(head) + datalen;
}
