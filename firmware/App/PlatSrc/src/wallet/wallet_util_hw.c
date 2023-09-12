#define LOG_TAG "wutil_hw"

#include <stdarg.h>
#include "common_c.h"
#include "wallet_util.h"
#include "sha3.h"
#include "device.h"
#include "rand.h"
#include "cdr.h"
#include "ex_types.h"
#include "libddi.h"
#include "wallet_util_hw.h"

#define RANDOM_DIGEST_LENGTH 32

#ifdef DEBUG_ON
static char debug_buffer[512] = {0};
#endif

int random_buffer(uint8_t *buf, size_t len) {
    return ddi_sec_get_randnum(buf, len);
}

static int _mix_random_digest(uint8_t *randata, size_t len) {
    int ret;
    unsigned char buff[64];
    SHA3_CTX context;
    if (len != RANDOM_DIGEST_LENGTH) {
        db_serr("invalid len:%d", len);
        return -1;
    }
    sha3_256_Init(&context);
    if (sec_read_chipid(buff) != 0) {
        return -1;
    }
    sha3_Update(&context, buff, 32);
    if (random_buffer(buff, 64) != 64) {
        db_serr("gen sys random false");
        return -1;
    }
    db_msg("rand %s", debug_bin_to_hex(buff, 64));
    sha3_Update(&context, buff, 64);

    uint32_t curr_tick = 0;
    ddi_sys_get_tick(&curr_tick);
    if (!curr_tick) {
        db_serr("gen curr_tick false");
        return -1;
    }
    sha3_Update(&context, (const unsigned char *) &curr_tick, 4);

    ret = device_get_cpuid((char *) buff, sizeof(buff));
    if (ret > 0) {
        sha3_Update(&context, buff, ret);
    }
    sha3_Update(&context, (const unsigned char *) &Global_Key_Random_Source, sizeof(Global_Key_Random_Source));

    if (ddi_sec_get_randnum(buff, 64) != 64) {
        db_serr("gen sapi random false");
        return -1;
    }
    sha3_Update(&context, buff, 64);
    sha3_Final(&context, randata);
    memset(buff, 0, sizeof(buff));
    return len;
}

int get_mix_random_buffer(uint8_t *buf, size_t len) {
    uint8_t tmpbuf[RANDOM_DIGEST_LENGTH];
    int left = len;
    uint8_t *p = buf;
    while (left > 0) {
        if (_mix_random_digest(tmpbuf, RANDOM_DIGEST_LENGTH) != RANDOM_DIGEST_LENGTH) {
            db_serr("gen random false");
            return -1;
        }
        memcpy(p, tmpbuf, left > RANDOM_DIGEST_LENGTH ? RANDOM_DIGEST_LENGTH : left);
        left -= RANDOM_DIGEST_LENGTH;
        p += RANDOM_DIGEST_LENGTH;
    }
    memzero(tmpbuf, sizeof(tmpbuf));
    db_secure("mix random %d : %s", len, debug_ubin_to_hex(buf, len));
    return (int) len;
}

int get_message_process_winid(const ProtoClientMessage *msg) {
    int winid;
    if (msg->type > 0x5 && msg->type < QR_MSG_BLE_DEVICE_STATE_REQUEST) {
        if (msg->type % 2 == 0) {
            return WINDOWID_TXSHOW;
        } else {
            db_error("invalid msg type:%d", msg->type);
            return 0;
        }
    }
    switch (msg->type) {
        case QR_MSG_BIND_ACCOUNT_REQUEST:
        case QR_MSG_GET_PUBKEY_REQUEST:
        case QR_MSG_FACTORY_INIT:
        case QR_MSG_USER_ACTIVE:
        case QR_MSG_BLE_DEVICE_STATE_REQUEST:
            winid = WINDOWID_QRPROC;
            break;
        default:
            db_error("invalid msg type:%d", msg->type);
            winid = 0;
    }
    return winid;
}

int get_coin_icon_path(int type, const char *uname, char *path, int size) {
    return -1;
}

#ifdef DEBUG_ON

void debug_printf(const char *fmt, ...) {
#if  DEBUG_UART || DEBUG_USB
    int size;
    if (!fmt) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    size = vsnprintf(debug_buffer, sizeof(debug_buffer), fmt, ap);
    va_end(ap);
    if (size < 0) {
        return;
    }
    const char *pt = debug_buffer;
    while (*pt != '\0') {
#if DEBUG_UART
        ddi_uart_write(0, (uint8_t *) pt, 1);
#elif DEBUG_USB
        ddi_usb_write((uint8_t *)pt, 1);
#endif
        pt++;
    }
#endif
}

void s_printhex(const char *s, uint8_t *data, int len) {
    int32_t i = 0;
    debug_printf("\r\n[%d][%s]:", len, s);
    for (i = 0; i < len; i++) {
        debug_printf("%02x ", data[i]);
    }
    debug_printf("\r\n");
}

#endif