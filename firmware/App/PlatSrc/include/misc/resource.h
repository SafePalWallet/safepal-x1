#ifndef WALLET_RES_H
#define WALLET_RES_H

#include "misc.h"
#include "cdr.h"
#include "cdrLang.h"

#include "ConfigKey.h"
#include "settings.h"
#include "map.h"

#define CSTATE_SP_CLICK 0x1
#define CSTATE_SP_ACTIVE 0x2

#define CFKEYX(m, s, x) ( 0x1000000 | ((x)&0xFF)<<16 | ((s)&0xFF)<<8 | ((m)&0xFF) )
#define CFKEYX2(ms, x)  ( 0x1000000 | ((x)&0xFF)<<16 | ((ms)&0xFFFF) )
#define CFKEY(m, s) ( ((s)&0xFF)<<8 | ((m)&0xFF) )

#define ICON_KEY(m) CFKEY(m,SK_icon)
#define ICON_STATE_KEY(m, x) CFKEYX(m,SK_icon,x)

#define SET_CSTATE_SP(s, p) (((s)&0x3F) | (((p)&0x3)<<6))
#define GET_CSTATE_SP(s) (((s)>>6)&0x3)
#define DROP_CSTATE_SP(s) ((s)&0x3F)

#define FONT_TYPE_SIZE 12

#define FONT_18 (3)
#define FONT_16 (4)
#define FONT_14 (5)
#define FONT_12 (11)

#define SCREEN_WIDTH  240
#define SCREEN_HEIGHT 240

#define IS_VALID_LANG_LABEL_ID(x) ((x)>=0 && (x)<LANG_LABEL_MAXID)

#define LANG_LABEL_NONE    0xFFFF

#define READ_BLOCK_SIZE 4096

typedef struct {
    uint8_t tag[4];
    uint32_t file_number;
    uint8_t check_code[4];
    uint32_t datasize;
    uint32_t version;
    uint8_t rsv[32];
} StrMergeFileHead;

typedef struct {
    uint32_t offset;
    uint32_t len;
    uint32_t index;
    uint8_t file_name[16];
    uint8_t check_code[4];
} StrMergeFileInfo;

#ifdef __cplusplus
extern "C" {
#endif

const char *res_getLabel(int labelIndex);

const char *res_getLangName(int index);

int res_updateLangAndFont(int newLang);

int res_initLangAndFont(void);

int res_get_label_version();

#ifdef __cplusplus
}
#endif

#endif
