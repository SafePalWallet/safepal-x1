#define LOG_TAG "dwin"

#include "common_c.h"
#include "dynamic_win.h"
#include "gui_api.h"
#include "key_event.h"
#include "cdr.h"

#define HWND_SIZE sizeof(HWND)

#define CTX_HWND_LEN(v) ((v)->labels->len / HWND_SIZE)

static unsigned char *gDispStr = NULL;

#ifdef BUILD_FOR_DEV
#define DISP_STR_SIZE (200*24)
#else
#define DISP_STR_SIZE (TEXT_MAX_LINE * 18)
#endif
#define ELLIPSIS "..."

int dwin_init(void) {
    db_msg("init view");

    if (!gDispStr) {
        db_msg("gDispStr to malloc");
        gDispStr = (unsigned char *) malloc(DISP_STR_SIZE);
        if (!gDispStr) {
            db_error("new gDispStr false");
            return -1;
        }
        memset(gDispStr, 0x0, DISP_STR_SIZE);
    }

    return 0;
}

int dwin_destory(void) {
    db_msg("destory view");
    if (gDispStr != NULL) {
        free(gDispStr);
        gDispStr = NULL;
    }
    return 0;
}

int dwin_add_txt(DynamicViewCtx *view, int mkey, int id, const char *value) {
    return dwin_add_txt_offset(view, mkey, id, value, 0);
}

static int SetWindowText(HWND hWnd, const char *spString) {
    if (is_empty_string(spString)) {
        db_error("invalid spString");
        return -1;
    }

    if (!gDispStr) {
        db_error("invalid gDispStr");
        return -2;
    }
    size_t current_len = strlen(gDispStr);
    size_t add_len = strlen(spString);
    size_t newline_len = 1;
    size_t ellipsis_len = strlen(ELLIPSIS);
    size_t max_available = DISP_STR_SIZE - current_len - 1;

    size_t required_len = current_len + add_len + newline_len;
    db_msg("add_len:%d, required_len:%d, max:%d", add_len, required_len, DISP_STR_SIZE);
    if (required_len < DISP_STR_SIZE) {
        strncat(gDispStr, spString, add_len);
        strncat(gDispStr, "\n", newline_len);
        return 0;
    }

    size_t available = DISP_STR_SIZE - current_len - 1;
    db_msg("available:%d, ellipsis_len:%d", available, ellipsis_len);
    if (available >= ellipsis_len) {
        size_t copy_len = available - ellipsis_len;
        if (copy_len > 0) {
            strncat(gDispStr, spString, copy_len);
        }
        strncat(gDispStr, ELLIPSIS, ellipsis_len);
    } else {
        size_t overwrite_count = ellipsis_len - max_available;
        size_t new_end = current_len - overwrite_count;
        gDispStr[new_end] = '\0';
        strncat(gDispStr, ELLIPSIS, ellipsis_len);
    }

    return 0;
}

int SetWindowMText(HWND hWnd, const char *spString) {
    if (spString && spString[0] == '{' && (spString[1] >= '0' && spString[1] <= '9')) {
        int f = spString[1] - '0';
        if (spString[2] == '}') {
            spString += 3;
        } else if ((spString[2] >= '0' && spString[2] <= '9') && spString[3] == '}') {
            f = f * 10 + (spString[2] - '0');
            spString += 4;
        }
        //SetWindowFont(hWnd, res_getFont(f));
    }
    return SetWindowText(hWnd, spString);
}

int dwin_add_txt_offset(DynamicViewCtx *view, int mkey, int id, const char *value, int offset) {
    db_msg("mkey:%d id:%d val:%s", mkey, id, value);
    if (is_empty_string(value)) {
        return -1;
    }
    SetWindowMText(0, value);
    return 0;
}

int ShowWindowTxt(const char *pTitle, uint32_t tType, const char *pCancel,const char *pOk) {
    db_msg("gDispStr:%s", gDispStr);
    int ret = gui_disp_info(pTitle, gDispStr, tType, pCancel, pOk, EVENT_KEY_F1);
    memset(gDispStr, 0x0, DISP_STR_SIZE);
    if (ret == EVENT_CANCEL) {
        return KEY_EVENT_ABORT;
    } else if (ret == EVENT_KEY_F1) {
        return RETURN_DISP_MAINPANEL;
    } else if (ret == EVENT_OK) {
        return 0;
    } else {
        return -1;
    }

    return 0;
}

