#define LOG_TAG "passwd_util"

#include <math.h>
#include "../../core/crypto/curves.h"
#include "common.h"
#include "passwd_util.h"
#include "secure_api.h"
#include "sha2.h"
#include "sha3.h"
#include "xstr.h"
#include "resource.h"
#include "Dialog.h"
#include "bip39_english.h"
#include "key_event.h"
#include "wallet_manager.h"
#include "device.h"
#include "pbkdf2.h"
#include "rand.h"
#include "global.h"
#include "gui_sdk.h"
#include "gui_api.h"
#include "ex_bt.h"
#include "FactoryWin.h"

static int check_input_passwd(const char *passwd, int len) {
    if (!passwd) {
        db_error("invalid paras null");
        return -1;
    }
    if (len != (int) strlen(passwd)) {
        db_error("invalid len:%d strlen:%d", len, strlen(passwd));
        return -1;
    }
    if (len < PASSWORD_MINI_LEN) {
        return USER_PASSWD_ERR_FORMAT;
    }
    if (len > PASSWORD_MAX_LEN) {
        return USER_PASSWD_ERR_FORMAT;
    }
    char n0 = *passwd;
    if (len == 6) {
        if (n0 == '1') {
            if (!strcmp(passwd, "123456")) return USER_PASSWD_ERR_WEAK;
            if (!strcmp(passwd, "123654")) return USER_PASSWD_ERR_WEAK;
            if (!strcmp(passwd, "111222")) return USER_PASSWD_ERR_WEAK;
        }
        if (n0 == '6' && !strcmp(passwd, "654321")) return USER_PASSWD_ERR_WEAK;
    }

    int i;
    for (i = 1; i < len; i++) {
        if (passwd[i] != n0) {
            break;
        }
    }
    if (i == len) { //all same
        return USER_PASSWD_ERR_WEAK;
    }

    for (i = 1; i < len; i++) {
        if (passwd[i] != n0 + i) {
            break;
        }
    }
    if (i == len) { //all ++
        return USER_PASSWD_ERR_WEAK;
    }

    for (i = 1; i < len; i++) {
        if (passwd[i] != n0 - i) {
            break;
        }
    }
    if (i == len) { //all --
        return USER_PASSWD_ERR_WEAK;
    }
    return 0;
}

static inline int ser_uint32(unsigned char *buf, uint32_t n) {
    buf[3] = (unsigned char) n;
    buf[2] = (unsigned char) (n >> 8);
    buf[1] = (unsigned char) (n >> 16);
    buf[0] = (unsigned char) (n >> 24);
    return sizeof(uint32_t);
}

//hash user original passwd for its sec chip
int hash_user_passwd(const char *passwd, int len, unsigned char hash[PASSWD_HASHED_LEN]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    const sec_base_info *binfo = wallet_getBaseInfo();
    if (!binfo || !binfo->chipid_len || !binfo->app_version || !binfo->chip_type) {
        ALOGE("get sec base info false");
        return -1;
    }
    const char *cpuid = device_get_cpuid_p();
    if (strlen(cpuid) != DEVICE_CPUID_LEN) {
        db_serr("get sechip id false");
        return -1;
    }
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, cpuid, DEVICE_CPUID_LEN);

#ifdef DB_DEBUG
    uint32_t t0 = 0;
    ddi_sys_get_tick(&t0);
#endif
    unsigned char salt[] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    XDEFINE_BUFFER(salt);
    //ALOGD("salt:%s", debug_ubin_to_hex(salt, sizeof(salt)));

    sha256_Update(&context, (const unsigned char *) passwd, len);

    memset(digest, 0, sizeof(digest));
    if (sec_read_chipid(digest) != 0) {
        db_error("get chipid false");
        return -1;
    }
    sha256_Update(&context, digest, 32);
    sha256_Update(&context, (const unsigned char *) passwd, len);
    sha256_Update(&context, (const unsigned char *) &(binfo->chip_type), sizeof(binfo->chip_type));
    sha256_Update(&context, binfo->chipid, binfo->chipid_len);
    sha256_Update(&context, salt, sizeof(salt));
    sha256_Update(&context, (const unsigned char *) passwd, len);
    sha256_Final(&context, digest);

    //hash again
    sha256_Init(&context);
    sha256_Update(&context, digest, 32);
    sha256_Update(&context, (const unsigned char *) passwd, len);
    if (sec_read_randkey(digest) != 32) {
        db_serr("read readkey faild");
        return -11;
    }
    sha256_Update(&context, digest, 32);
    sha256_Update(&context, (const unsigned char *) passwd, len);
    sha256_Final(&context, digest);

    //db_secure("digest 0:%s", debug_ubin_to_hex(digest, SHA256_DIGEST_LENGTH));
    pbkdf2_hmac_sha256((const unsigned char *) passwd, len, digest, SHA256_DIGEST_LENGTH, 2048, hash,
                       SHA256_DIGEST_LENGTH);
    db_secure("hash:%s", debug_ubin_to_hex(hash, PASSWD_HASHED_LEN));
    memset(digest, 0, sizeof(digest));
    memset(salt, 0, sizeof(salt));
    memset(&binfo, 0, sizeof(binfo));
#ifdef DB_DEBUG
    uint32_t t1;
    ddi_sys_get_tick(&t1);
    db_debug("use time:%lld ms", t1 - t0);
#endif
    return PASSWD_HASHED_LEN;
}

USER_PASSWD_ERR
passwdKeyboard(HWND hParent, const char *title, const int opType, unsigned char passhash[PASSWD_HASHED_LEN],
               unsigned int flag) {
    if (NULL == passhash) {
        db_error("invalid paras passhash");
        return USER_PASSWD_ERR_INVALID_PARAS;
    }
    char kb_result[PASSWORD_MAX_LEN + 1] = {0};
    int ret = 0;
    int err = 0;
    int passwdLen = 0;
    char tips[64] = {0};

    do {
        memset(kb_result, 0, sizeof(kb_result));
        ret = gui_show_edit_box(IME_PWD, IME_NUM, TEXT_ALIGN_CENTER, title, NULL, kb_result, PASSWORD_MINI_LEN,
                                PASSWORD_MAX_LEN, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
        db_msg("enter ret:%d", ret);
        if (ret == KEY_EVENT_BACK) {
            memset(kb_result, 0, sizeof(kb_result));
            return USER_PASSWD_ERR_ABORT;
        } else if (ret == EVENT_KEY_F1) {
            memset(kb_result, 0, sizeof(kb_result));
            return RETURN_DISP_MAINPANEL;
        } else if (ret == OPER_LESS_MIN) {
            if (opType == PIN_CODE_CHECK) {
                ret = gui_disp_info(title, res_getLabel(LANG_LABEL_SET_PIN_LEN_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL,
                                    res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                if (ret == EVENT_KEY_F1) {
                    memset(kb_result, 0, sizeof(kb_result));
                    return RETURN_DISP_MAINPANEL;
                }
                continue;
            } else {
                if (is_not_empty_string(kb_result)) {
                    db_msg("kb_result:%s", kb_result);
                } else {
                    continue;
                }
            }
        } else if (ret < 0) {
            db_error("passwd input error ret:%d", ret);
            memset(kb_result, 0, sizeof(kb_result));
            dialog_error3(hParent, ret, "Password error.");
            err = 1;
            break;
        }

        passwdLen = strlen(kb_result);
        if (opType == PIN_CODE_VERITY) {
            ret = hash_user_passwd((const char *) kb_result, passwdLen, passhash);
            if (ret < 0) {
                memset(kb_result, 0, sizeof(kb_result));
                memzero(passhash, PASSWD_HASHED_LEN);
                dialog_error3(hParent, ret, "Password error.");
                continue;
            }
            ret = sapi_check_passwd(passhash, PASSWD_HASHED_LEN);
            db_msg("sapi_check_passwd ret:%x", ret);
            int subcode = sapi_subcode;
            if (ret == 0) {
                GLobal_PIN_Passed = 1;
                if (flag & PASSKB_FLAG_RAW_PASSWD) {
                    memzero(passhash, PASSWD_HASHED_LEN);
                    memcpy(passhash, kb_result, PASSWORD_MAX_LEN);
                }
                memset(kb_result, 0, sizeof(kb_result));
                return USER_PASSWD_ERR_NONE;
            }
            memset(kb_result, 0, sizeof(kb_result));
            memzero(passhash, PASSWD_HASHED_LEN);
            switch (ret) {
                case ERROR_SERVICE_DENY:
                case ERROR_PASSWD_ERROR_MUCH: {
                    gui_disp_info(res_getLabel(LANG_LABEL_PASSWD_ERROR_SIMPLE),
                                  res_getLabel(LANG_LABEL_PASSWD_ERROR_MUCH_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL,
                                  res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    GLobal_PIN_Passed = 0;
                    wallet_destorySeed(0, 0);
                    doFactoryReset();
                    sec_reset_randkey(0);
                    if (!(flag & PASSKB_FLAG_NOT_SWITCH_GUIDE)) {
                        ddi_sys_reboot();
                    }
                    return USER_PASSWD_ERR_VERIFY;
                }
                    break;
                case ERROR_PASSWD_NO_MATCH: {
                    char state = (subcode >> 8) & 0XFF;
                    char errTimes = subcode & 0xFF;
                    db_msg("err times:%d state:%d", errTimes, state);
                    int retain = wallet_getPasswdAllowErrorTimes() - errTimes;
                    if (retain <= 0) {
                        dialog_error(hParent, res_getLabel(LANG_LABEL_PASSWD_ERROR_MUCH_TIPS));
                        db_msg("Too many input errors. The wallet has been reset. Please recover with correct mnemonic phrase.");
                        GLobal_PIN_Passed = 0;
                        wallet_destorySeed(0, 0);
                        doFactoryReset();
                        if (!(flag & PASSKB_FLAG_NOT_SWITCH_GUIDE)) {
                            ddi_sys_reboot();
                        }
                        return USER_PASSWD_ERR_VERIFY;
                    } else {
                        if (retain <= 3) {
                            snprintf(tips, sizeof(tips), res_getLabel(LANG_LABEL_PASSWD_ERROR), retain);
                        } else {
                            snprintf(tips, sizeof(tips), "%s", res_getLabel(LANG_LABEL_PASSWD_ERROR_SIMPLE));
                        }
                        gui_disp_info(res_getLabel(LANG_LABEL_PASSWD_ERROR_TITLE), tips,
                                      TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK),
                                      EVENT_KEY_F1);
                        db_msg("Try again");
                    }
                }
                    break;
                default: {
                    //dialog_error3(hParent, sapi_subcode, "Password error");
                    err = 1;
                }
                    break;
            }
        } else {
            if (opType == PIN_CODE_CHECK) {
                ret = check_input_passwd((const char *) kb_result, passwdLen);
                db_secure("check passwd ret:%d", ret);
                if (ret != 0) {
                    switch (ret) {
                        case USER_PASSWD_ERR_WEAK: {
                            gui_disp_info(res_getLabel(LANG_LABEL_PASSWD_ERROR_WEAK_TITLE),
                                          res_getLabel(LANG_LABEL_PASSWD_ERROR_WEAK_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                          res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK),
                                          EVENT_KEY_F1);
                        }
                            break;
                        case USER_PASSWD_ERR_FORMAT:
                        case USER_PASSWD_ERR_NOT_INPUT: {
                            gui_disp_info(res_getLabel(LANG_LABEL_PASSWD_ERROR_FORMAT_TITLE),
                                          res_getLabel(LANG_LABEL_SET_PIN_LEN_TIPS),
                                          TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                          res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                        }
                            break;
                        default:
                            err = 1;
                            break;
                    }
                    continue;
                }
            }
            ret = hash_user_passwd((const char *) kb_result, passwdLen, passhash);
            if (ret < 0) {
                memset(kb_result, 0, sizeof(kb_result));
                memzero(passhash, PASSWD_HASHED_LEN);
                //dialog_error3(hParent, ret, "Password error");
                db_error("hash user passwd false ret:%d", ret);
                return USER_PASSWD_ERR_SYSTEM;
            }
            if (flag & PASSKB_FLAG_RAW_PASSWD) {
                memzero(passhash, PASSWD_HASHED_LEN);
                memcpy(passhash, kb_result, PASSWORD_MAX_LEN);
            }
            memset(kb_result, 0, sizeof(kb_result));
            return USER_PASSWD_ERR_NONE;
        }
    } while (!err);
    memset(kb_result, 0, sizeof(kb_result));
    memzero(passhash, PASSWD_HASHED_LEN);
    return USER_PASSWD_ERR_SYSTEM;
}

USER_PASSWD_ERR checkPasswdKeyboard(HWND hParent, const char *title, unsigned int flag) {
    unsigned char passhash[PASSWD_HASHED_LEN];
    USER_PASSWD_ERR ret = passwdKeyboard(hParent, title, PIN_CODE_VERITY, passhash, flag | PASSKB_FLAG_RANDOM);
    //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
    memzero(passhash, sizeof(passhash));
    return ret;
}
