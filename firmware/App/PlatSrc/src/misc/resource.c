#define LOG_TAG "Resource"

/*
NOTE:Because LANG_NAME_MAP, This file should with BOM.
*/

#include "libddi.h"
#include "resource.h"
#include "update.h"
#include "common_core.h"
#include "sha2.h"

static int mLang = CONFIG_DEFAULT_LANG;
static char **mLangLabel = NULL;
static char *mLangLabelBuffer = NULL;
static int mLangLabelSize = 0;
static int mLabelVersion = 0;

static const char *LANG_FILE_MAP[LANG_MAXID] = {
        "en",
        "zh-CN",
        "zh-TW",
        "jpn",
        "korean",
        "german",
        "french",
        "italian",
        "spanish",
        "vietnam",
        "russia",
        "portugal",
        "idn",//indonesia
        "turkey",
        "thailand",
};

static const char *LANG_NAME_MAP[LANG_MAXID] = {
        "English",
        "简体中文",
        "繁體中文",
        "日本語",
        "한국어",
        "Deutsch",
        "Français",
        "Italiano",
        "Español",
        "Tiếng Việt",
        "Pусский",
        "Português",
        "Indonesia",
        "Türkçe",
        "ภาษาไทย",
};


const char *res_getLangName(int index) {
    return IS_VALID_LANG_ID(index) ? LANG_NAME_MAP[index] : LANG_NAME_MAP[LANG_EN];
}

static int res_loadLabelFileToBuffer(uint32_t addr, uint32_t filesize) {
    if (mLangLabelBuffer != NULL) {
        free(mLangLabelBuffer);
        mLangLabelBuffer = NULL;
    }
    if (mLangLabel != NULL) {
        free(mLangLabel);
        mLangLabel = NULL;
        mLangLabelSize = 0;
    }

    if (filesize < 10 || filesize > 16 * 1024) {
        db_error("invalid filesize:%d", filesize);
        return -1;
    }
    mLangLabelBuffer = (char *) malloc(filesize + 1);
    if (mLangLabelBuffer == NULL) {
        db_error("new memory:%d false", filesize);
        return -1;
    }
    ddi_flash_read(addr, (unsigned char *) mLangLabelBuffer, filesize);
    mLangLabelBuffer[filesize] = 0;

    int linenum = 0;
    char *s;
    char *p = mLangLabelBuffer;
    char *pend = mLangLabelBuffer + filesize;
    //count line number
    while (p < pend) {
        if (*p == '\n') {
            linenum++;
        }
        p++;
    }
    db_msg("line num:%d", linenum);

    mLangLabel = (char **) malloc(linenum * sizeof(char *));
    if (mLangLabel == NULL) {
        db_error("new memory false");
        free(mLangLabelBuffer);
        return -1;
    }
    mLangLabelSize = linenum;

    linenum = 0;
    s = mLangLabelBuffer;
    p = mLangLabelBuffer;
    while (p < pend) {
        if (*p == '\r') {
            *p = 0;
            p++;
        }
        if (*p == '\n') {
            *p = 0;
            mLangLabel[linenum] = s; //save line
            linenum++;
            s = p + 1;
        }
        if (*p == '\\' && *(p + 1) == 'n') {
            *p++ = ' ';
            *p = '\n';
        }
        p++;
    }
#if 0
    //show result
   linenum = 0;
   while (linenum < mLangLabelSize) {
       db_msg("line:%d text:%s", linenum, res_getLabel(linenum));
       linenum++;
   }
#endif
    return 0;
}

void res_set_label_version(int version) {
    mLabelVersion = version;
}

int res_get_label_version() {
    return mLabelVersion;
}

int res_loadLabelFromLangFile(const char *langFile) {
    int ret;
    StrMergeFileHead fileHead;
    StrMergeFileInfo fileInfo;
    int i = 0;
    int fileInfoLen = 0;

    if (is_empty_string(langFile)) {
        db_error("invalid langFile name");
        return -1;
    }

    memset(&fileHead, 0x0, sizeof(StrMergeFileHead));
    memset(&fileInfo, 0x0, sizeof(StrMergeFileInfo));

    ddi_flash_read(INTERNAL_LANG_LABEL_ADDR, (uint8_t *) &fileHead, sizeof(StrMergeFileHead));
    if (strncmp(fileHead.tag, "LABE", sizeof(fileHead.tag))) {
        db_error("tag is error!!!");
        return -1;
    }

    if ((fileHead.file_number <= 0) || (fileHead.file_number > 30)) {
        db_error("file_number is error!!!file_number:%d", fileHead.file_number);
        return -2;
    }

    if (fileHead.version < 10000) {
        db_error("version is error!!!version:%d", fileHead.version);
        return -3;
    }
    int data_size = fileHead.datasize;
    if (data_size < 1024 || data_size > 512 * 1024) {
        db_error("invalid datasize:%d", data_size);
        return -4;
    }
    res_set_label_version(fileHead.version);

    int readlen = 0, readed = 0, pos = 0;
    SHA256_CTX context;
    unsigned char digest[32] = {0};
    unsigned char *buffer = NULL;
    buffer = (unsigned char *) malloc(READ_BLOCK_SIZE);
    if (!buffer) {
        db_error("buffer is error!");
        return -4;
    }

    pos = INTERNAL_LANG_LABEL_ADDR + sizeof(StrMergeFileHead) + sizeof(StrMergeFileInfo) * fileHead.file_number;
    sha256_Init(&context);
    while (data_size > 0) {
        readlen = data_size > READ_BLOCK_SIZE ? READ_BLOCK_SIZE : data_size;
        ret = ddi_flash_read(pos + readed, buffer, readlen);
        if (ret > 0) {
            sha256_Update(&context, buffer, ret);
            data_size -= ret;
            readed += ret;
        } else {
            break;
        }
    }
    sha256_Final(&context, digest);
    if (memcmp(digest, fileHead.check_code, 4)) {
        db_error("error digest:%s", debug_bin_to_hex(digest, 4));
        db_error("need check_code:%s", debug_bin_to_hex(fileHead.check_code, 4));
        free(buffer);
        return -2;
    }
    free(buffer);

    fileInfoLen = sizeof(StrMergeFileInfo) * fileHead.file_number;

    ddi_flash_read(INTERNAL_LANG_LABEL_ADDR + sizeof(StrMergeFileHead), (uint8_t *) &fileInfo, sizeof(StrMergeFileInfo));
    if (fileInfo.offset != (sizeof(StrMergeFileHead) + fileInfoLen)) {
        db_error("fileInfo.offset is error!!!offset_b:%d", fileInfo.offset);
        return -3;
    }

    db_msg("file_number:%d", fileHead.file_number);
    db_msg("datasize:%d", fileHead.datasize);
    db_msg("file_name:%s", fileInfo.file_name);
    db_msg("len:%d", fileInfo.len);

    for (i = 0; i < fileHead.file_number; i++) {
        memset(&fileInfo, 0x0, sizeof(StrMergeFileInfo));
        ddi_flash_read(INTERNAL_LANG_LABEL_ADDR + sizeof(StrMergeFileHead) + (sizeof(StrMergeFileInfo) * i), (uint8_t *) &fileInfo, sizeof(StrMergeFileInfo));
        db_msg("i:%d, name:%s, len:%d, offset:%d", i, fileInfo.file_name, fileInfo.len, fileInfo.offset);

        if ((fileInfo.len == 0) || (fileInfo.len > (15 * 1024))) {
            db_error("invalid len:%d", fileInfo.len);
            return -4;
        }

        if (strcmp(fileInfo.file_name, langFile) == 0) {
            db_msg("find %s", langFile);
            ret = res_loadLabelFileToBuffer(INTERNAL_LANG_LABEL_ADDR + fileInfo.offset, fileInfo.len);
            db_msg("load ret:%d", ret);
            return ret;
        }
    }

    memset(&fileHead, 0x0, sizeof(StrMergeFileHead));
    memset(&fileInfo, 0x0, sizeof(StrMergeFileInfo));

    return 0;
}

static int res_initLangLabel() {
    if (!IS_VALID_LANG_ID(mLang)) {
        db_error("lang is no initialized");
        return -1;
    }

    char dataFile[48];
    snprintf(dataFile, sizeof(dataFile), "%s.bin", LANG_FILE_MAP[mLang]);
    db_msg("dataFile:%s", dataFile);
    if (res_loadLabelFromLangFile(dataFile) < 0) {
        db_error("load label from %s failed", dataFile);
        return -1;
    }
    db_msg("use lang:%s", dataFile);
    return 0;
}

const char *res_getLabel(int labelIndex) {
    if (labelIndex >= 0 && labelIndex < mLangLabelSize) {
        return mLangLabel[labelIndex];
    } else {
        db_msg("invalide label Index: %d, size is %d", labelIndex, mLangLabelSize);
        return "";
    }
}

int res_updateLangAndFont(int newLang) {
    if (!IS_VALID_LANG_ID(newLang)) {
        db_error("error lang:%d", newLang);
        return -1;
    }
    if (newLang == mLang)
        return 0;
    mLang = newLang;
    db_msg("new lang is:%d", mLang);
    res_initLangLabel(); /* init lang labels */
    return 0;
}

int res_initLangAndFont(void) {
    mLang = settings_get_lang();
    db_msg("lang:%d", mLang);

    res_initLangLabel(); /* init lang labels */

    return 0;
}
