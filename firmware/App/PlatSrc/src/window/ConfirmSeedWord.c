#define LOG_TAG "ConfirmSeedWord"

/*
NOTE:Because "√", This file should with BOM.
*/

#include "ex_types.h"
#include "debug.h"
#include "confirmseedword.h"
#include "bip39_english.h"
#include "gui_sdk.h"
#include "key_event.h"
#include "wallet_util.h"
#include "gui_api.h"

#define ITEM_SELECT_POOL_MAX 8
#define ITEM_MAX_CNT 3

typedef struct {
    int curConfirmIdx;
    int selectedIdx;
    uint16_t items[ITEM_MAX_CNT];
    ConfirmSeedWordConfig_t *config;
} ConfirmSeedWordState;

static int reloadData(ConfirmSeedWordState *state) {
    if (NULL == state) {
        db_error("invalid state:%p", state);
        return -1;
    }
    int i = 0;
    ConfirmSeedWordConfig_t *config = state->config;
    uint16_t cur_value = state->config->seeds[state->curConfirmIdx];
    db_msg("current confirm index:%d,cur_value:%d", state->curConfirmIdx, cur_value);
    int startPool = 0;
    uint16_t pools[ITEM_SELECT_POOL_MAX];
    if ((config->seedWordCnt - state->curConfirmIdx) > ITEM_SELECT_POOL_MAX) {
        startPool = state->curConfirmIdx;
    } else {
        startPool = config->seedWordCnt - ITEM_SELECT_POOL_MAX;
    }
    for (i = 0; i < ITEM_SELECT_POOL_MAX; i++) {
        pools[i] = state->config->seeds[startPool + i];
    }
    upset_array(pools, ITEM_SELECT_POOL_MAX);

    bool find = false;
    for (i = 0; i < ITEM_MAX_CNT; ++i) {
        state->items[i] = pools[i];
        if (pools[i] == cur_value) {
            find = true;
        }
    }
    if (!find) {
        //i = random32() % ITEM_MAX_CNT;//hard fault
        uint8_t rand = 0;
        ddi_sec_get_randnum(&rand, 1);
        i = rand % ITEM_MAX_CNT;
        state->items[i] = cur_value;
    }
    state->selectedIdx = 0;
    return 0;
}

static int show_select_result(int index, char *menuText[ITEM_MAX_CNT], int state) {
    int i = 0;
    strRect rect;

    memset(&rect, 0x0, sizeof(strRect));

    for (i = 0; i < 3; i++) {
        if (index == i) {
            rect.m_x0 = 0;
            rect.m_x1 = g_gui_info.uiScrWidth;
            rect.m_y0 = (i + 1) * g_gui_info.uiLineHeight;
            rect.m_y1 = (i + 2) * g_gui_info.uiLineHeight;
            ddi_lcd_clear_rect(&rect);
            ddi_lcd_show_text(g_gui_info.uiScrWidth - 12, rect.m_y0, (state == 1) ? "√" : "X");
        }
        ddi_lcd_show_text(1, (i + 1) * g_gui_info.uiLineHeight, menuText[i]);
    }
    ddi_lcd_brush_screen();
    ddi_sys_msleep(300);

    return 0;
}

static int reloadUI(ConfirmSeedWordState *state) {
    if (NULL == state) {
        db_error("invalid state:%p", state);
        return -1;
    }

    char str[64] = {0};
    int ret = 0;
    char *menuText[ITEM_MAX_CNT];
    uint8_t title[16] = {0};
    int i = 0;
    memset(menuText, 0x0, sizeof(menuText));
    memset(title, 0x0, sizeof(title));
    for (i = 0; i < ITEM_MAX_CNT; ++i) {
        menuText[i] = (char*)wordlist[state->items[i]];
    }
    snprintf(title, sizeof(title), "Word %d", state->curConfirmIdx + 1);
    ret = gui_show_menu(title, ITEM_MAX_CNT, 0, menuText, TEXT_ALIGN_LEFT, NULL, NULL, EVENT_NONE);
    if (ret == KEY_EVENT_BACK) {
        return KEY_EVENT_BACK;
    } else if (ret < 0) {
        return KEY_EVENT_ABORT;
    } else {
        if (state->config->seeds[state->curConfirmIdx] == state->items[ret]) {
            //state->itemState = ITEM_STATE_RIGHT;
            state->curConfirmIdx++;

            if (state->curConfirmIdx == state->config->seedWordCnt) {
                show_select_result(ret, menuText, 1);
                return 0;//finish
            } else {
                show_select_result(ret, menuText, 1);
                return 1;//next
            }
        } else {
            //state->itemState = ITEM_STATE_ERR;
            show_select_result(ret, menuText, 0);
            return 2;//continue
        }
    }

    return -1;
}

int showConfirmSeedWord(ConfirmSeedWordConfig_t *config) {
    ConfirmSeedWordState state;
    int ret = -1;

    memset(&state, 0, sizeof(ConfirmSeedWordState));
    state.config = config;
    state.curConfirmIdx = 0;

    while (1) {
        reloadData(&state);
        ret = reloadUI(&state);
        if (ret > 0) {
            continue;
        } else {
            break;//
        }

        ddi_sys_msleep(30);
    }

    return ret;
}
