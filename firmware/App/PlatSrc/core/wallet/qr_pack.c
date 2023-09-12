#define LOG_TAG "qr_pack"

#include <stdlib.h>
#include <string.h>
#include "defines.h"

#ifdef IOS_APP
#include "aes.h"
#include "sha2.h"
#include <CommonCrypto/CommonDigest.h>
#else

#include <sha2.h>

#endif

#include "qr_pack.h"
#include "secure_util.h"
//#include "base64.h"
#include "debug.h"
#include "protobuf_util.h"
#include "common_util.h"

static const char *QRCODE_PREFIX_BIN = "B:";
static const char *QRCODE_PREFIX_NOTIFY_BIN = "C:";

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifdef IOS_APP
#define sha256_Raw(data,len,digest) CC_SHA256((data),(len),(digest))
#endif

void init_qr_packet(qr_packet *p, unsigned int data_size) {
    memset(p, 0, sizeof(qr_packet));
    if (data_size) {
        p->data = cstr_new_sz(data_size);
    }
}

void free_qr_packet(qr_packet *p) {
    if (p->data != NULL) {
        cstr_free(p->data);
        p->data = NULL;
    }
    memset(p, 0, sizeof(qr_packet));
}

int qr_packet_ext_header_length(const qr_packet *p) {
    size_t len = 0;
    if (p && p->data) {
        if (p->flag & QR_FLAG_HAS_TIME) {
            len += 6;
            if (p->data->len < len) { //error
                db_error("invalid data len:%d < time len:6", p->data->len);
                return -1;
            }
        }
        if (p->flag & QR_FLAG_EXT_HEADER) {
            if (p->data->len < (len + 11)) {
                db_error("invalid data len:%d from len:%d", p->data->len, len);
                return -1;
            }
            if (p->data->str[len] != 0x7a) { //tag string 15
                return -1;
            }
            uint32_t low = 0;
            uint32_t hi = 0;
            len += 1;
            len += pb_decode((uint8_t *) (p->data->str + len), &low, &hi); //varlen
            if (hi != 0 || low >= 0x4000) {
                db_error("invalid ext header var len:%d %d", low, hi);
                return -1;
            }
            len += low;
            if (p->data->len < len) {
                db_error("invalid data len:%d < %d varlen:%d", p->data->len, len, low);
                return -1;
            }
        }
    }
    return (int) len;
}

const unsigned char *qr_packet_ext_header_str(const qr_packet *p, int ext_header_len) {
    return (ext_header_len > 0 && (int) p->data->len > ext_header_len) ? (const unsigned char *) p->data->str : NULL;
}

int qr_packet_data_length(const qr_packet *p, int ext_header_len) {
    if (ext_header_len < 0) {
        ext_header_len = qr_packet_ext_header_length(p);
        if (ext_header_len < 0) return 0;
    }
    if (p && p->data) {
        int len = p->data->len - ext_header_len;
        if (len > 0) {
            if (p->p_total > 1) {
                return len - QR_HASH_CHECK_LEN;
            } else {
                return len;
            }
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

const unsigned char *qr_packet_data_str(const qr_packet *p, int ext_header_len) {
    if (ext_header_len < 0) {
        ext_header_len = qr_packet_ext_header_length(p);
        if (ext_header_len < 0) return 0;
    }
    if (p && p->data) {
        if ((int) p->data->len > ext_header_len) {
            return (const unsigned char *) (p->data->str + ext_header_len);
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }
}

int set_qr_packet(qr_packet *p, const char *data, size_t size) {
    if (p->data) {
        cstr_free(p->data);
    }
    p->data = cstr_new_buf(data, size);

    if (p->data == NULL) {
        return -1;
    }
    return size;
}

int free_qr_buffer(qr_packet_buffer *buffer) {
    int i;
    int max = buffer->p_total < MAX_QR_BUFFER_SIZE ? buffer->p_total : MAX_QR_BUFFER_SIZE;
    for (i = 0; i < max; i++) {
        if (buffer->chunks[i]) {
            cstr_free(buffer->chunks[i]);
            buffer->chunks[i] = NULL;
        }
    }
    memset(buffer, 0, sizeof(qr_packet_buffer));
    return 0;
}

int is_bin_qr_packet(const char *data, size_t size) {
    if (size >= QRCODE_PREFIX_LEN && data[1] == ':') {
        if (*data == QRCODE_PREFIX_BIN[0]) {
            return 1;
        }
        if (*data == QRCODE_PREFIX_NOTIFY_BIN[0]) {
            return 3;
        }
    }
    return 0;
}

int parse_qr_packet_header_info(const char *data, size_t size, qr_packet_header_info *h) {
    if (!data) {
        db_error("not bin qr packet");
        return -1;
    }
    if (size < (QRCODE_PREFIX_LEN + QR_PACKET_HEADER_LEN)) {
        db_error("small size:%ld", size);
        return -1;
    }
    unsigned char *rawdata = (unsigned char *) data + QRCODE_PREFIX_LEN;
    qr_packet_header *header = (qr_packet_header *) rawdata;
    unsigned int n = header->nbit;
    unsigned int version = n & 0x3;
    unsigned int df = (n >> 2) & 0x1;    //Don't Fragment
    unsigned int mf = (n >> 3) & 0x1;    //More Fragments
    unsigned int header_len = ((n >> 4) & 0xF) * 2;

    uint16_t packet_len = ntohs(header->length);

    if (version < 1 || version > QRCODE_PACKET_VERSION) {
        db_error("error version:%d", version);
        return -1;
    }
    if (header_len != QR_PACKET_HEADER_LEN && header_len != (QR_PACKET_HEADER_LEN + QR_PACKET_CHUNK_HEADER_LEN)) {
        db_error("invalid header len:%d", header_len);
        return -2;
    }

    if (df == 1 && mf != 0) {
        db_error("error df:%d mf:%d", df, mf);
        return -3;
    }

    uint16_t p_total = 1;
    uint16_t p_index = 0;

    if (df == 0 && h->p_total != 0xFF) { //use h->p_total == 0xFF as flag,not parse chunk header
        if (size < QRCODE_PREFIX_LEN + QR_PACKET_HEADER_LEN + QR_PACKET_CHUNK_HEADER_LEN) {
            db_error("miss chunk header,size:%d", size);
            return -11;
        }
        qr_packet_chunk_header *header2 = (qr_packet_chunk_header *) (rawdata + QR_PACKET_HEADER_LEN);
        p_total = header2->p_total;
        p_index = header2->p_index;
        //db_debug("header2 chunk total:%d index:%d", p_total, p_index);

        if (p_total <= 0 || p_index >= p_total) {
            db_error("error total:%d index:%d df:%d mf:%d", p_total, p_index, df, mf);
            return -12;
        }
        if (mf == 0 && (p_index + 1 != p_total)) {
            db_error("error total:%d index:%d df:%d mf:%d", p_total, p_index, df, mf);
            return -13;
        }
    }

    h->version = version;
    h->header_length = header_len;
    h->mf = mf;
    h->df = df;
    h->data_length = packet_len - header_len;
    h->type = header->type;
    h->flag = header->flag;
    h->client_id = header->client_id;
    memcpy(h->checkcode, header->checkcode, sizeof(h->checkcode));

    h->p_total = p_total;
    h->p_index = p_index;

    return 0;
}

int decode_qr_packet(const char *data, size_t size, qr_packet *packet) {
    int ret = is_bin_qr_packet(data, size);
    if (!ret) {
        db_error("not bin qr packet");
        return -1;
    }
    int isbase64 = (ret == 2);
    unsigned char *rawdata;
    int bin_len;
    if (isbase64) {
        return -1;
    } else {
        rawdata = (unsigned char *) data + QRCODE_PREFIX_LEN;
        bin_len = size - QRCODE_PREFIX_LEN;
    }
    ret = -1;
    do {
        if (bin_len < QR_PACKET_HEADER_LEN) {
            db_error("error content len:%d", bin_len);
            break;
        }

        qr_packet_header *header = (qr_packet_header *) rawdata;
        unsigned int n = header->nbit;
        unsigned int version = n & 0x3;
        unsigned int df = (n >> 2) & 0x1;    //Don't Fragment
        unsigned int mf = (n >> 3) & 0x1;    //More Fragments
        unsigned int header_len = ((n >> 4) & 0xF) * 2;

        uint16_t type = header->type;
        uint16_t packet_len = ntohs(header->length);

        /*db_debug("header len:%d n:%d mf:%d df:%d version:%d type:%d flag:%d packet len:%d checkcode:%s",
                 header_len, n, mf, df, version, type, header->flag, packet_len, debug_ubin_to_hex(header->checkcode, QR_HASH_CHECK_LEN));*/

        if (version < 1 || version > QRCODE_PACKET_VERSION) {
            db_error("error version:%d", version);
            break;
        }
        if (header_len != QR_PACKET_HEADER_LEN && header_len != (QR_PACKET_HEADER_LEN + QR_PACKET_CHUNK_HEADER_LEN)) {
            db_error("invalid header len:%d", header_len);
            break;
        }

        if (bin_len < packet_len || packet_len <= header_len) {
            db_error("invalid bin len:%d header_len:%d packet_len:%d", bin_len, header_len, packet_len);
            break;
        }

        if (df == 1 && mf != 0) {
            db_error("error df:%d mf:%d", df, mf);
            break;
        }

        packet_len -= header_len;

        uint16_t p_total = 1;
        uint16_t p_index = 0;

        if (df == 0) {
            if (bin_len < QR_PACKET_HEADER_LEN + QR_PACKET_CHUNK_HEADER_LEN) {
                db_error("miss chunk header,len:%d", bin_len);
                break;
            }
            qr_packet_chunk_header *header2 = (qr_packet_chunk_header *) (rawdata + QR_PACKET_HEADER_LEN);
            p_total = header2->p_total;
            p_index = header2->p_index;
            //db_debug("header2 chunk total:%d index:%d", p_total, p_index);

            if (p_total <= 0 || p_index >= p_total) {
                db_error("error total:%d index:%d df:%d mf:%d", p_total, p_index, df, mf);
                break;
            }
            if (mf == 0 && (p_index + 1 != p_total)) {
                db_error("error total:%d index:%d df:%d mf:%d", p_total, p_index, df, mf);
                break;
            }
        }

        packet->type = type;
        packet->p_total = p_total;
        packet->p_index = p_index;
        packet->client_id = header->client_id;
        packet->flag = header->flag;

        // check code
        unsigned char digest[SHA256_DIGEST_LENGTH];
        sha256_Raw(rawdata + header_len, packet_len, digest);
        if (memcmp(digest, header->checkcode, QR_HASH_CHECK_LEN) != 0) {
            db_error("check code failed execpted:%s current:%x%x%x%x", debug_ubin_to_hex(header->checkcode, QR_HASH_CHECK_LEN), digest[0], digest[1], digest[2], digest[3]);
            break;
        }
        if (set_qr_packet(packet, (const char *) rawdata + header_len, packet_len) != packet_len) {
            db_error("set_buf false len:%d", packet_len);
            break;
        }
        ret = 0;
    } while (0);
    return ret;
}

int merge_qr_packet_buffer(qr_packet_buffer *buffer, qr_packet *mrg_pkt, const char *data, size_t size) {
    qr_packet _qr;
    qr_packet *qr = &_qr;
    if (buffer == NULL) {
        db_error("error buffer paras");
        return QR_DECODE_SYSTEM_ERR;
    }

    if (!is_bin_qr_packet(data, size)) {
        db_error("qr not isBinPacket, data:%p", data);
        return QR_DECODE_INVALID_DATA;
    }

    init_qr_packet(&_qr, 0);

    if (decode_qr_packet(data, size, qr) != 0) {
        db_error("decode qr packet size:%d false", (int) size);
        free_qr_packet(qr);
        return QR_DECODE_PACKET_FAILED;
    }
    /*db_msg("decode qr packet type:%d client:%d index:%d total:%d sz:%d",
           qr->type, qr->client_id, qr->p_index, qr->p_total, (qr->data ? qr->data->len : 0));*/

    if (qr->p_total > MAX_QR_BUFFER_SIZE) {
        db_error("total:%d > %d", qr->p_total, MAX_QR_BUFFER_SIZE);
        free_qr_packet(qr);
        return QR_DECODE_OVER_BUFF_SIZE;
    }

    int i = 0;
    int totalsize = 0;
    if (!buffer->p_total || qr->client_id != buffer->client_id || qr->type != buffer->type || qr->p_total != buffer->p_total) {
        i = 1;
    }

    if (i) {
        free_qr_buffer(buffer);
        buffer->type = qr->type;
        buffer->p_total = qr->p_total;
        buffer->client_id = qr->client_id;

        mrg_pkt->type = qr->type;
        mrg_pkt->p_total = qr->p_total;
        mrg_pkt->flag = qr->flag;
        mrg_pkt->client_id = qr->client_id;
    }

    if (buffer->chunks[qr->p_index]) {
        cstr_free(buffer->chunks[qr->p_index]);
    }
    buffer->chunks[qr->p_index] = qr->data;

    if (qr->p_index == 0) {
        mrg_pkt->flag = qr->flag; //use 1st flag
    }

    int totalitem = 0;
    for (i = 0; i < buffer->p_total; i++) {
        if (buffer->chunks[i]) {
            totalitem++;
            totalsize += buffer->chunks[i]->len;
        }
    }
    mrg_pkt->p_index = ((totalitem > 0) ? (totalitem - 1) : 0); //use index as have scaned size

    if (totalitem < buffer->p_total) {
        return 1; //not finish
    }

    cstring *result;
    if (buffer->p_total == 1) {
        result = buffer->chunks[0];
        buffer->chunks[0] = NULL;
    } else {
        result = cstr_new_sz(totalsize);
        if (!result) {
            db_error("new cstring size:%d false", totalsize);
            return QR_DECODE_SYSTEM_ERR;
        }
        for (i = 0; i < buffer->p_total; i++) {
            if (!cstr_append_cstr(result, buffer->chunks[i])) {
                db_error("append buffer size:%d false", totalsize);
                return QR_DECODE_SYSTEM_ERR;
            }
        }
    }
    mrg_pkt->data = result;
    return 0;
}

int decrypt_qr_packet(qr_packet *mrg_pkt, const unsigned char *sekey) {
    if (mrg_pkt == NULL || sekey == NULL) {
        db_error("decrypt qr packet false, packet:%p, sekey:%p", mrg_pkt, sekey);
        return -1;
    }
    if (!mrg_pkt->data) {
        db_debug("qr packet not data");
        return -1;
    }

    if (!(mrg_pkt->flag & QR_FLAG_CRYPT_AES)) {
        db_debug("qr packet not encrypt");
        return 0;
    }
    int total_len = mrg_pkt->data->len;
    int data_len = total_len;
    if (mrg_pkt->p_total > 1) {
        data_len = total_len - QR_HASH_CHECK_LEN;
        if (data_len <= 0) {
            db_error("invalid packet len:%d p_total:%d", total_len, mrg_pkt->p_total);
            return -1;
        }
    }

    unsigned char *tmpbuff = (unsigned char *) malloc(total_len);
    if (!tmpbuff) {
        db_error("malloc size:%d false", total_len);
        return -1;
    }
    //db_msg("before decrypt:%s", debug_bin_to_hex(mrg_pkt->data->str, data_len));
    if (aes256_decrypt((const unsigned char *) mrg_pkt->data->str, tmpbuff, data_len, sekey) != 0) {
        db_error("decrypt false packet:%p, sekey:%p", mrg_pkt, sekey);
        return -1;
    }
    //db_msg("after decrypt:%s", debug_ubin_to_hex(tmpbuff, data_len));

    if (mrg_pkt->p_total > 1) { //copy check hask code
        memcpy(tmpbuff + data_len, mrg_pkt->data->str + data_len, QR_HASH_CHECK_LEN);
        db_msg("hash code:%s", debug_bin_to_hex(mrg_pkt->data->str + data_len, QR_HASH_CHECK_LEN));
    }

    cstr_set_buf(mrg_pkt->data, tmpbuff, total_len);
    free(tmpbuff);
    mrg_pkt->flag &= ~QR_FLAG_CRYPT_AES;

    db_debug("decrypt true");
    return 0;
}

int verify_qr_packet(qr_packet *mrg_pkt) {
    if (mrg_pkt->p_total <= 1) { //not need
        return 0;
    }
    int datalen = mrg_pkt->data->len - QR_HASH_CHECK_LEN;
    if (datalen <= 0) {
        db_error("invalid packet len:%d p_total:%d", mrg_pkt->data->len, mrg_pkt->p_total);
        return -1;
    }
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    sha256_Raw((const uint8_t *) mrg_pkt->data->str, datalen, digest);
    if (memcmp(mrg_pkt->data->str + datalen, digest, QR_HASH_CHECK_LEN) != 0) {
        db_error("invalid packet hash len:%d expect:%s digest:%x%x%x%x", mrg_pkt->data->len, debug_bin_to_hex(mrg_pkt->data->str + datalen, QR_HASH_CHECK_LEN),
                 digest[0], digest[1], digest[2], digest[3]);
        return -1;
    }
    return 0;
}

int get_qr_packet_header_len(int have_chunk) {
    int len = QR_PACKET_HEADER_LEN;
    if (have_chunk > 0) {
        len += QR_PACKET_CHUNK_HEADER_LEN;
    }
    return len;
}

static unsigned char *encode_qr_packet(const unsigned char *data, size_t size, int qrtype, int msg_type, int flag,
                                       int client_id, int total, int current, size_t *packet_size) {

    if (data == NULL || size <= 0) {
        db_error("encode qr packet data null");
        return NULL;
    }
    if (qrtype != QR_TYPE_BIN) {
        db_error("unsupport type:%d", qrtype);
        return NULL;
    }
    int headerlen = QR_PACKET_HEADER_LEN;
    int df = 1;
    int mf = 0;
    if (total > 1) {
        headerlen += QR_PACKET_CHUNK_HEADER_LEN;
        df = 0;
        if (current + 1 != total) {
            mf = 1;
        }
    }
    int totallen = size + headerlen;
    int packetLen = QRCODE_PREFIX_LEN + totallen;

    unsigned char *rawdata = (unsigned char *) malloc(packetLen);
    unsigned char *p;
    if (!rawdata) {
        db_error("malloc memory size:%d false,", packetLen);
        return NULL;
    }
    memset(rawdata, 0, packetLen);
    memcpy(rawdata, QRCODE_PREFIX_BIN, QRCODE_PREFIX_LEN);
    p = rawdata + QRCODE_PREFIX_LEN;

    *p++ = ((QRCODE_PACKET_VERSION & 0x3) | (df << 2) | (mf << 3) | ((headerlen / 2) << 4));
    *p++ = (unsigned char) msg_type;

    *p++ = (unsigned char) flag;
    *p++ = (unsigned char) client_id;

    // checkcode sha256(data)
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Raw(data, size, digest);
    //db_debug("sha256 digest:%s", (char *) debug_bin_to_hex((char *) digest, QR_HASH_CHECK_LEN));
    memcpy(p, digest, QR_HASH_CHECK_LEN);

    p += QR_HASH_CHECK_LEN;

    *p++ = (unsigned char) ((totallen >> 8) & 0xFF);
    *p++ = (unsigned char) totallen;

    if (total > 1) {
        *p++ = (unsigned char) total;
        *p++ = (unsigned char) current;
    }

    memcpy(rawdata + QRCODE_PREFIX_LEN + headerlen, data, size);

    if (packet_size != NULL) {
        *packet_size = packetLen;
    }
    return rawdata;
}

int split_qr_packet(qr_packet_chunk_info *chunk_result, const unsigned char *qrdata, int size, int qrtype, int msg_type, int flag,
                    int client_id, const unsigned char *sekey, int max_chunk_size) {
    const unsigned char *qr_result = qrdata;
    unsigned char *crypted_buff = NULL;
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    int ret;
    int result_code = -1;

    if (max_chunk_size < 32) { //check arg first
        db_error("invalid max_chunk_size:%d", max_chunk_size);
        return -1;
    }
    if (qrtype != QR_TYPE_BIN) {
        db_error("unsupport type:%d", qrtype);
        return -1;
    }

    sha256_Raw(qrdata, size, digest);
    chunk_result->total = 0;
    chunk_result->chunks = NULL;

    max_chunk_size -= QRCODE_PREFIX_LEN;

    if (flag & QR_FLAG_CRYPT_AES) {
        crypted_buff = (unsigned char *) malloc(size);
        if (!crypted_buff) {
            db_error("new crypted_buff false");
            return -1;
        }
        ret = aes256_encrypt(qrdata, crypted_buff, size, sekey);
        if (ret != 0) {
            db_error("encrypt false");
            return -1;
        }
        qr_result = crypted_buff;
    }

    int len = get_qr_packet_header_len(0);
    int total = 0;
    int i;
    do {
        if (len + size <= max_chunk_size) { // only 1 packet
            len = size;
            total = 1;
        } else {
            len = max_chunk_size - get_qr_packet_header_len(1); // max per chunk size
            total = (size + QR_HASH_CHECK_LEN + len - 1) / len;
            len = (size + QR_HASH_CHECK_LEN + total - 1) / total; //avg per chunk size

            db_msg("qrsize:%d max_chunk_size:%d prechunk:%d total:%d", size, max_chunk_size, len, total);
        }

        chunk_result->chunks = (qr_packet_chunk_slice *) malloc(sizeof(qr_packet_chunk_slice) * total);
        if (!chunk_result->chunks) {
            db_error("new chunks buff false");
            break;
        }
        memset(chunk_result->chunks, 0, sizeof(qr_packet_chunk_slice) * total);

        unsigned char *qrbin;
        int offset = 0;
        int have_err = 0;
        int sendlen;
        size_t packsize;
        for (i = 0; i < total; i++) {
            packsize = 0;
            if (total == 1) { //only 1 packet
                sendlen = size;
                qrbin = encode_qr_packet(qr_result, sendlen, qrtype, msg_type, flag, client_id, total, i, &packsize);
            } else if (i == (total - 1)) { //end last chunk
                if (size > offset) {
                    unsigned char *tmpbuf = (unsigned char *) malloc(max_chunk_size);
                    if (tmpbuf == NULL) {
                        db_error("new tmp buff false len:%d", max_chunk_size);
                        have_err++;
                        break;
                    }

                    memcpy(tmpbuf, qr_result + offset, size - offset);
                    memcpy(tmpbuf + (size - offset), digest, QR_HASH_CHECK_LEN);
                    sendlen = QR_HASH_CHECK_LEN + (size - offset);

                    qrbin = encode_qr_packet(tmpbuf, sendlen, qrtype, msg_type, flag, client_id, total, i, &packsize);
                    free(tmpbuf);
                } else {
                    sendlen = QR_HASH_CHECK_LEN;
                    qrbin = encode_qr_packet(digest, sendlen, qrtype, msg_type, flag, client_id, total, i, &packsize);
                }
            } else {
                sendlen = len;
                qrbin = encode_qr_packet(qr_result + offset, sendlen, qrtype, msg_type, flag, client_id, total, i, &packsize);
                offset += sendlen;
            }
            if (qrbin) {
                chunk_result->chunks[i].data = qrbin;
                chunk_result->chunks[i].size = packsize;
                //db_msg("size:%d index:%d total:%d packsize:%d", size, i, total, packsize);
            } else {
                have_err++;
                db_error("encode_qr_packet i:%d total:%d false", i, total);
                break;
            }
        }

        if (have_err) {
            for (i = 0; i < total; i++) {
                if (!chunk_result->chunks[i].data) break;
                free(chunk_result->chunks[i].data);
                chunk_result->chunks[i].data = NULL;
                chunk_result->chunks[i].size = 0;
            }
            free(chunk_result->chunks);
            chunk_result->chunks = NULL;
            break;
        } else {
            chunk_result->total = total;
        }
        result_code = 0;
    } while (0);

    if (crypted_buff) {
        free(crypted_buff);
        crypted_buff = NULL;
    }
    return result_code;
}

int free_qr_packet_chunk(qr_packet_chunk_info *chunk_result) {
    if (!chunk_result) {
        return -1;
    }
    int i;
    if (chunk_result->total > 0 && chunk_result->chunks) {
        for (i = 0; i < chunk_result->total; i++) {
            if (chunk_result->chunks[i].data) {
                free(chunk_result->chunks[i].data);
                chunk_result->chunks[i].size = 0;
            }
        }
    }
    chunk_result->total = 0;
    if (chunk_result->chunks) {
        free(chunk_result->chunks);
        chunk_result->chunks = NULL;
    }
    return 0;
}

int qr_packet_get_len(const char *data, size_t size) {
    qr_packet_header_info h;
    if (data == NULL) {
        db_error("error buffer paras");
        return QR_DECODE_SYSTEM_ERR;
    }

    int ret = is_bin_qr_packet(data, size);
    if (!ret) {
        db_error("qr not isBinPacket, data:%p", data);
        return QR_DECODE_INVALID_DATA;
    } else if (ret == 3) {
        return QR_DECODE_NOTIFY_MSG;
    }

    h.p_total = 0xFF;
    ret = parse_qr_packet_header_info(data, size, &h);
    if (ret != 0) {
        db_error("decode qr packet size:%d false,ret:%d", (int) size, ret);
        return QR_DECODE_PACKET_FAILED;
    }

    ret = h.data_length;
    if (h.df == 0) {
        ret += sizeof(qr_packet_chunk_header);
    }
    return ret;
}
