#define LOG_TAG "setting"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "settings.h"
#include "debug.h"
#include "global.h"
#include "device.h"
#include "common_c.h"
#include "wallet_manager.h"
#include "ex_lcd.h"
#include "libddi.h"

//size: 120 bytes
typedef struct {
    char mDeviceName[32];
    unsigned char HaveSeed;
    unsigned char mFTStep;
    unsigned char mLang;
    unsigned char _reserve_char[5];
    int mOtaPreVersion;
    int mCoinsVersion;
    int mTimeZone;
    int mScreenSaver;
    int mAutoShutdownTime;
    int mBrightness;
    int mRandPinKeypad;
    int mAccountType;
    char _reserve[48];
} Settings_Nvm_Info;

#define DEVICE_NAME_SIZEOF 32
static char mDeviceName[DEVICE_NAME_SIZEOF];
static unsigned int gSync2NvmIndex = 0;
SettingsInfo gSettings[1] = {0};

static const char *LANG_SUFIX[LANG_MAXID] = {
        "en",
        "cn",
        "tw",
        "jp",
        "kr",
        "de",
        "fr",
        "it",
        "es",
        "vn",
        "ru",
        "pt",
        "id",
        "tr",
        "th",
};

void settings_set_default() {
    gHaveSeed = 0;
    gSettings->mOtaPreVersion = 0;
    gSettings->mCoinsVersion = 0;
    gSettings->mTimeZone = 0;

    gSettings->mFTStep = 0;
    gSettings->mScreenSaver = 30;
    gSettings->mAutoShutdownTime = 45;
    gSettings->mBrightness = 3;//BRIGHTNESS_LEVEL_3;
    gSettings->mRandPinKeypad = 1;//OFF
    gSettings->mAccountType = 0;//unknow
    memset(mDeviceName, 0, DEVICE_NAME_SIZEOF);
}

//$<|%s|>$
static int decode_setting_value(const char *val, char *dst, int size) {
    size--;
    int vallen = strlen(val);
    int offset = 0;
    int len = vallen;
    if (vallen >= 6 && val[0] == '$' && val[1] == '<' && val[2] == '|') {
        char *p = strrchr(val + 3, '|');
        if (p && (p - val) == (vallen - 3) && *(p + 1) == '>' && *(p + 2) == '$') {
            offset = 3;
            len = vallen - 6;
        }
    }
    if (len > size) {
        len = size;
    }
    strncpy(dst, val + offset, len);
    dst[len] = '\0';
    return len;
}

#define CHECK_KEY(k, v)  if(key[0]==(k)[0] && !strcmp(key, k)){ target = &v; break;}

static int *findKey2Value(const char *key) {
    int *target = NULL;
    //check val
    do {
        CHECK_KEY(SETTING_KEY_HAVE_SEED, gHaveSeed)
        CHECK_KEY(SETTING_KEY_LANGUAGE, gSettings->mLang)
        CHECK_KEY(SETTING_KEY_TIMEZONE, gSettings->mTimeZone)
        CHECK_KEY(SETTING_KEY_AUTO_SHUTDOWN_TIME, gSettings->mAutoShutdownTime)
        CHECK_KEY(SETTING_KEY_SCREEN_SAVER, gSettings->mScreenSaver)
        CHECK_KEY(SETTING_KEY_OTA_PRE_VERSION, gSettings->mOtaPreVersion)
        CHECK_KEY(SETTING_KEY_COINS_VERSION, gSettings->mCoinsVersion)
        CHECK_KEY(SETTING_KEY_FT_STEP, gSettings->mFTStep)
        CHECK_KEY(SETTING_KEY_BRIGHTNESS, gSettings->mBrightness)
        CHECK_KEY(SETTING_KEY_RAND_PIN_KEYPAD, gSettings->mRandPinKeypad)
        CHECK_KEY(SETTING_KEY_ACCOUNT_TYPE, gSettings->mAccountType)

        db_error("unknow config key:%s", key);
    } while (0);
    return target;
}

static int try_backup_to_nvm(const char *key) {
    /*if (Global_App_Inited) {
        gSync2NvmIndex++;
    } else*/ {
        settings_backup_to_nvm(1);
    }
    return 0;
}

int settings_backup_to_nvm(int force) {
    Settings_Nvm_Info info;
    if (!force && !gSync2NvmIndex) {
        return 0;
    }
    gSync2NvmIndex = 0;

    memset(&info, 0, sizeof(info));
    strlcpy(info.mDeviceName, mDeviceName, DEVICE_NAME_SIZEOF);

    info.HaveSeed = gHaveSeed;
    info.mLang = gSettings->mLang;
    info.mScreenSaver = gSettings->mScreenSaver;
    info.mAutoShutdownTime = gSettings->mAutoShutdownTime;
    info.mOtaPreVersion = gSettings->mOtaPreVersion;
    info.mCoinsVersion = gSettings->mCoinsVersion;
    info.mFTStep = gSettings->mFTStep;
    info.mTimeZone = gSettings->mTimeZone;
    info.mBrightness = gSettings->mBrightness;
    info.mRandPinKeypad = gSettings->mRandPinKeypad;
    info.mAccountType = gSettings->mAccountType;

    int ret = device_save_settings((const unsigned char *) &info, sizeof(info));
    db_msg("save nvm setting ret:%d", ret);
    return ret;
}

static int settings_read_from_nvm() {
    Settings_Nvm_Info info;
    memset(&info, 0, sizeof(info));
    int ret = device_read_settings((unsigned char *) &info, sizeof(info));
    db_msg("read nvm setting ret:%d", ret);
    if (ret < (int) sizeof(info)) {
        return -1;
    }
    db_msg("info name:%s", info.mDeviceName);
    unsigned char *p = (unsigned char *) &info;
    p += sizeof(info.mDeviceName);
    db_msg("info hex:%s", debug_ubin_to_hex(p, sizeof(info) - sizeof(info.mDeviceName) - sizeof(info._reserve)));

    strlcpy(mDeviceName, info.mDeviceName, DEVICE_NAME_SIZEOF);
    gHaveSeed = info.HaveSeed;
    gSettings->mLang = info.mLang;
    gSettings->mScreenSaver = info.mScreenSaver;
    gSettings->mAutoShutdownTime = info.mAutoShutdownTime;
    gSettings->mOtaPreVersion = info.mOtaPreVersion;
    gSettings->mCoinsVersion = info.mCoinsVersion;
    gSettings->mFTStep = info.mFTStep;
    gSettings->mTimeZone = info.mTimeZone;
    gSettings->mBrightness = info.mBrightness;
    gSettings->mRandPinKeypad = info.mRandPinKeypad;
    gSettings->mAccountType = info.mAccountType;

    return 0;
}

static int _read_callback(void *user, const char *key, const char *val) {
    db_msg("read_callback %s = %s ", key, val);
    if (strlen(val) == 0) {
        return 0;
    }

    if (*key == 'D' && !strcmp(key, SETTING_KEY_DEVICE_NAME)) {
        decode_setting_value(val, mDeviceName, DEVICE_NAME_SIZEOF - 1);
        return 0;
    }
    int *target = findKey2Value(key);
    if (target != NULL) {
        *target = atoi(val);
        return 0;
    }
    return 0;
}

int settings_init() {
    int need_read_nvm = 1; //read nvm default
    memset((unsigned char *) &gSettings, 0, sizeof(gSettings));
    gSettings->mLang = CONFIG_DEFAULT_LANG;
    settings_set_default();
    //int have_ota_ok = ddi_vfs_access(OTA_SUCCESS_FILE, F_OK) ? 0 : 1;
    db_msg("loading %s,gHaveSeed=%d", CDR_SETTINGS_FILE, gHaveSeed);
    if (ddi_vfs_access(CDR_SETTINGS_FILE) == 0) {
        config_file_read(CDR_SETTINGS_FILE, _read_callback, 0);
    } else {
        need_read_nvm++;
    }
    if (!gHaveSeed) {
        need_read_nvm++;
    }
    if (gHaveSeed && !gSettings->mCoinsVersion) {
        need_read_nvm++;
    }
    if (gHaveSeed && !mDeviceName[0]) {
        need_read_nvm++;
    }
    if (need_read_nvm) {
        db_msg("need_read_nvm:%d", need_read_nvm);
        settings_read_from_nvm();
    }
    if (gSettings->mLang > LANG_MAXID) {
        gSettings->mLang = CONFIG_DEFAULT_LANG;
    }

    if (!gHaveSeed) {
        uint64_t id = device_read_seed_account();
        if (id) {
            db_debug("found seed account:%llx auto set have seed", id);
            settings_set_have_seed(id);
        }
    }

    if (gSettings->mBrightness < 0 || \
        gSettings->mBrightness > 4) {
        gSettings->mBrightness = 2;
    }
    ddi_lcd_ioctl(DDI_LCD_CTL_BRIGHT, (uint32_t) gSettings->mBrightness, 0);

    //set auto sleep
    if ((gSettings->mScreenSaver > 60) || (gSettings->mScreenSaver <= 0)) {
        gSettings->mScreenSaver = 30;
    }
    if ((gSettings->mAutoShutdownTime > 120) || (gSettings->mAutoShutdownTime <= 0)) {
        gSettings->mAutoShutdownTime = 45;
    }
    db_msg("mScreenSaver:%d,mAutoShutdownTime:%d", gSettings->mScreenSaver, gSettings->mAutoShutdownTime);
    ddi_sys_cmd(SYS_CMD_SET_AUTO_SLEEP_TIME, gSettings->mScreenSaver, 0);
    ddi_sys_cmd(SYS_CMD_SET_INTO_DEEPSLEEP_TIME, gSettings->mAutoShutdownTime, 0);
    ddi_sys_cmd(SYS_CMD_SET_AUTO_SLEEP_AVAIBLE, 1, NULL);
    ddi_sys_cmd(SYS_CMD_SET_OTHER_KEY_WKUP, 1, 0);

    return 0;
}

int settings_save(const char *key, int val) {
    int ret = config_file_set_int(CDR_SETTINGS_FILE, key, val);
    if (ret == 0) {
        int *target = findKey2Value(key);
        if (target != NULL) {
            *target = val;
        }
        try_backup_to_nvm(key);
    }
    return ret;
}

int settings_save_string(const char *key, const char *value) {
    int ret;
    char tmpbuf[128];
    int len = strlen(value);
    if (len > 120) {
        db_error("key:%s too long:%d value:%s", key, len, value);
        return -1;
    }
    //encode string
    int upatelocal = 1;
    int havespace = 0;
    const char *p = value;
    while (*p) {
        if (isspace(*p)) {
            havespace = 1;
            break;
        }
        p++;
    }
    if (havespace) {
        snprintf(tmpbuf, sizeof(tmpbuf), "$<|%s|>$", value);
        db_msg("---1 key=%s,tmpbuf=%s", key, tmpbuf);
        ret = config_file_set(CDR_SETTINGS_FILE, key, tmpbuf);
    } else {
        db_msg("---2 key=%s,value=%s", key, value);
        ret = config_file_set(CDR_SETTINGS_FILE, key, value);
    }
    if (ret == 0 && upatelocal) {
        _read_callback(0, key, value);
    }
    return ret;
}

int settings_get_string(const char *key, char *value, int size) {
    return config_file_get(CDR_SETTINGS_FILE, key, value, size);
}

int settings_get(const char *key, int default_val) {
    return config_file_get_int(CDR_SETTINGS_FILE, key, default_val);
}

int settings_have_set(const char *key) {
    char value[32];
    return config_file_get(CDR_SETTINGS_FILE, key, value, 32) > 0;
}

int settings_get_lang() {
    return IS_VALID_LANG_ID(gSettings->mLang) ? gSettings->mLang : CONFIG_DEFAULT_LANG;
}

int settings_get_all_langs(int langs[LANG_MAXID]) {
    int n = 0;
    langs[n++] = LANG_EN;
    langs[n++] = LANG_FR;
    langs[n++] = LANG_ES;
    langs[n++] = LANG_IT;
    langs[n++] = LANG_PT;
    langs[n++] = LANG_JP;
    langs[n++] = LANG_KR;
    langs[n++] = LANG_RU;
    langs[n++] = LANG_TW;
    langs[n++] = LANG_CN;
//    langs[n++] = LANG_DE;
//    langs[n++] = LANG_TR;
//    langs[n++] = LANG_TH;
//    langs[n++] = LANG_VN;
//    langs[n++] = LANG_ID;

    return n;
}


const char *settings_get_lang_suffix() {
    return IS_VALID_LANG_ID(gSettings->mLang) ? LANG_SUFIX[gSettings->mLang] : LANG_SUFIX[LANG_EN];
}

const char *settings_get_ui_suffix() {
    return "";
}

int settings_get_screen_saver_time() {
    if (app_run_in_dev_mode()) {
        return 0;
    } else {
        return (Global_Temp_Screen_Time < 0) ? 0 : (gSettings->mScreenSaver + Global_Temp_Screen_Time);
    }
}

int settings_get_auto_shutdown_time() {
    return gSettings->mAutoShutdownTime;
}

void settings_set_have_seed(uint64_t id) {
    Global_Device_Account_Index++;
    int state = id ? 1 : 0;
    device_save_seed_account(id);
    if (!state) {
        gSeedAccountId = 0;
    }
    settings_save(SETTING_KEY_HAVE_SEED, state); //auto save nvm
    gHaveSeed = state;
    db_msg("SETTING_KEY_HAVE_SEED set %d,get %d", state, settings_get(SETTING_KEY_HAVE_SEED, 3));
}

int get_device_name(char *name, int size, int suffix) {
    char buff[32];
    const char *device_name = mDeviceName;
    if (!mDeviceName[0]) {
        device_name = PRODUCT_BRAND_VALUE;
    }
    memset(buff, 0, sizeof(buff));
    if (suffix && gSeedAccountId) {
        wallet_getAccountSuffix(buff);
    }
    if (buff[0]) {
        return snprintf(name, size, "%s-%s", device_name, buff);
    } else {
        return strlcpy(name, device_name, size);
    }
}

int settings_set_device_name(const char *name) {
    memset(mDeviceName, 0, DEVICE_NAME_SIZEOF);
    Global_Device_Account_Index++;
    settings_save_string(SETTING_KEY_DEVICE_NAME, name);
    if (is_not_empty_string(name)) {
        strlcpy(mDeviceName, name, DEVICE_NAME_SIZEOF);
    }
    try_backup_to_nvm(SETTING_KEY_DEVICE_NAME);
    return 0;
}
