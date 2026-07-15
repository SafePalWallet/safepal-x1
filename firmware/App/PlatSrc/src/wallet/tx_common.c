#define LOG_TAG "TxCommon"

#include "tx_common.h"
#include "wallet_proto.h"
#include "debug.h"
#include "sha2.h"

int GetExtHeaderLen(const ProtoClientMessage *msg) {
    size_t len = 0;
    if (msg && msg->data) {
        if (msg->flag & QR_FLAG_HAS_TIME) {
            len += 6;
            if (msg->data->len < len) { //error
                db_error("invalid data len:%d < time len:6", msg->data->len);
                return -1;
            }
        }
        if (msg->flag & QR_FLAG_EXT_HEADER) {
            if (msg->data->len < (len + 11)) {
                db_error("invalid data len:%d from len:%d", msg->data->len, len);
                return -2;
            }
            if (msg->data->str[len] != 0x7a) { //tag string 15
                return -3;
            }
            uint32_t low = 0;
            uint32_t hi = 0;
            len += 1;
            len += pb_decode((uint8_t *) (msg->data->str + len), &low, &hi); //varlen
            if (hi != 0 || low >= 0x4000) {
                db_error("invalid ext header var len:%d %d", low, hi);
                return -4;
            }
            len += low;
            if (msg->data->len < len) {
                db_error("invalid data len:%d < %d varlen:%d", msg->data->len, len, low);
                return -5;
            }
        }
    }
    return (int) len;
}

int TxGetVerifyCode(const ProtoClientMessage *msg) {
    SHA256_CTX context;
    char sn[24];
    int ret;
    char unique_id[CLIENT_UNIQID_MAX_LEN + 1];
    char str[32];
    uint8_t digest[32];

    sha256_Init(&context);

    //sn
    memzero(sn, sizeof(sn));
    ret = device_get_sn(sn, 24);
    if (ret <= 0) {
        db_error("get SN error, ret:%d", ret);
        return -10;
    }
    db_msg("sn:%s", sn);
    sha256_Update(&context, sn, ret);
    //unique_id
    memzero(unique_id, sizeof(unique_id));
    ret = storage_queryClientUniqueId(msg->client_id, unique_id);
    if ((ret != 0) || (!is_safe_string(unique_id, CLIENT_UNIQID_MAX_LEN))) {
        db_error("get unique id error, ret:%d", ret);
        return -11;
    }
    db_msg("unique_id:%s", unique_id);
    sha256_Update(&context, unique_id, strlen(unique_id));
    //client_id
    memzero(str, sizeof(str));
    snprintf(str, sizeof(str), "%d", msg->client_id);
    db_msg("msg->client_id:%d, str:%s", msg->client_id, str);
    sha256_Update(&context, str, strlen(str));
    //account_id
    uint64_t account_id = wallet_AccountId();
    db_msg("account_id:%u, msg->account_id:%u", (uint32_t) account_id, msg->account_id);
    if ((uint32_t) account_id != msg->account_id) {
        db_error("not same, local (uint32_t) account_id:%u, msg->account_id:%u", (uint32_t) account_id, msg->account_id);
        return -12;
    }
    memzero(str, sizeof(str));
    snprintf(str, sizeof(str), "%u", msg->account_id);
    db_msg("account_id:%s", str);
    sha256_Update(&context, str, strlen(str));
    //data
    int ext_header_len = GetExtHeaderLen(msg);
    db_msg("ext_header_len:%d, msg->data->len:%d", ext_header_len, msg->data->len);
    if (ext_header_len < 0) {
        db_error("get ext header false ext_header_len:%d", ext_header_len);
        return -13;
    }
    int data_len = msg->data->len - ext_header_len;
    if (msg->p_total > 1) {
        data_len -= QR_HASH_CHECK_LEN;
    }
    sha256_Update(&context, msg->data->str + ext_header_len, data_len);
    sha256_Final(&context, digest);
    db_msg("digest:%s", debug_ubin_to_hex(digest, 32));
    sha256_Raw(digest, 32, digest);
    db_msg("digest:%s", debug_ubin_to_hex(digest, 32));
    unsigned int n = read_be(digest);
    n = n % 1000000;
    if (!n) n = 1;
    return n;
}
