#ifndef WALLET_SETTINGS_H
#define WALLET_SETTINGS_H

#include "config.h"
#include "platform.h"
#include "defines.h"

#ifdef DEBUG_ON
#define APP_VERSION_PREFIX "D"
#else
#define APP_VERSION_PREFIX "V"
#endif

#define DEVICE_APP_INT_VERSION  10008
#define DEVICE_APP_VERSION  APP_VERSION_PREFIX"1.0.8"

#define COINS_INIT_VERSION 5

#define DEVICE_PRODUCT_SERIES  "WALLET_X1"
#define DEVICE_PRODUCT_TYPE    "X1_R31"
#define PRODUCT_TYPE_S1_R31
#define DEVICE_PRODUCT_NAME    "X1"
#define DEVICE_PRODUCT_BRAND   "SafePal"

#define PRODUCT_SERIES_VALUE    DEVICE_PRODUCT_SERIES
#define PRODUCT_TYPE_VALUE      DEVICE_PRODUCT_TYPE
#define PRODUCT_NAME_VALUE      DEVICE_PRODUCT_NAME
#define PRODUCT_BRAND_VALUE     DEVICE_PRODUCT_BRAND

#ifndef PRODUCT_VERSION
#define PRODUCT_VERSION     PRODUCT_TYPE_VALUE "-" DEVICE_APP_VERSION
#endif

#define SETTING_KEY_LANGUAGE "Language"
#define SETTING_KEY_SCREEN_SAVER "ScreenSaver"
#define SETTING_KEY_TIMEZONE "TimeZone"
#define SETTING_KEY_AUTO_SHUTDOWN_TIME "AutoShutdownTime"
#define SETTING_KEY_DEVICE_NAME "DeviceName"

#define SETTING_KEY_HAVE_SEED "HaveSeed"

#define SETTING_KEY_BTC_MAX_INDEX "BtcMaxIndex"
#define SETTING_KEY_OTA_PRE_VERSION "OtaPreVersion"
#define SETTING_KEY_FT_STEP "FTStep"
#define SETTING_KEY_BRIGHTNESS "Brightness"
#define SETTING_KEY_RAND_PIN_KEYPAD "RandPinKeypad"
#define SETTING_KEY_ACCOUNT_TYPE "AccountType"

#define SETTING_KEY_PKEY   "PKey"

#define SETTING_KEY_COINS_VERSION  "CoinsVersion"

#define CDR_SETTINGS_FILE DATA_PATH"wallet.cfg"

#ifdef DEVICE_PRODUCT_DEFAULT_LANG
#undef CONFIG_DEFAULT_LANG
#define CONFIG_DEFAULT_LANG DEVICE_PRODUCT_DEFAULT_LANG
#endif

#ifndef CONFIG_DEFAULT_LANG
#define CONFIG_DEFAULT_LANG LANG_EN
#endif

enum {
    LANG_EN = 0,
    LANG_CN = 1,
    LANG_TW = 2,
    LANG_JP = 3,
    LANG_KR = 4,
    LANG_DE = 5,
    LANG_FR = 6,
    LANG_IT = 7,
    LANG_ES = 8,
    LANG_VN = 9,
    LANG_RU = 10,
    LANG_PT = 11,
    LANG_ID = 12,
    LANG_TR = 13,
    LANG_TH = 14,
    LANG_MAXID
};

#define IS_VALID_LANG_ID(x) ((x)>=0 && (x)<LANG_MAXID)
#define LANG_SHOW_ABOUT_WITH_BACK_ICON (-99)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int mLang;
    int mOtaPreVersion;
    int mCoinsVersion;
    int mFTStep;
    int mTimeZone;
    int mScreenSaver;
    int mAutoShutdownTime;
    int mBrightness;
    int mRandPinKeypad;
    int mAccountType;
} SettingsInfo;

extern SettingsInfo gSettings[1];

int settings_backup_to_nvm(int force);

int settings_init(void);

void settings_set_default(void);

int settings_get_string(const char *key, char *value, int size);

int settings_get(const char *key, int default_val);

int settings_save(const char *key, int val);

int settings_save_string(const char *key, const char *value);

int settings_have_set(const char *key);

int settings_get_lang(void);

int settings_get_all_langs(int langs[LANG_MAXID]);

const char *settings_get_lang_suffix(void);

const char *settings_get_ui_suffix(void);

int settings_get_screen_saver_time(void);

int settings_get_auto_shutdown_time(void);

void settings_set_have_seed(uint64_t id);

int get_device_name(char *name, int size, int suffix);

int settings_set_device_name(const char *name);

#ifdef __cplusplus
}
#endif
#endif
