#define LOG_TAG "BtProc"

#include "BtProcWin.h"
#include <string.h>
#include "ex_types.h"
#include "ex_key.h"
#include "debug.h"
#include "pvt_util.h"
#include "global.h"
#include "device.h"
#include "bignum.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "secure_api.h"
#include "gui_sdk.h"
#include "SettingWin.h"
#include "CoinsWin.h"
#include "libddi.h"
#include "active_util.h"
#include "wallet_proto.h"
#include "wallet_util.h"
#include "loading_win.h"
#include "gui_api.h"
#include "BtProcWin.h"
#include "wallet_util_hw.h"
#include "dialog.h"
#include "wallet_manager.h"
#include "common_util.h"
#include "BtRecvCode.h"
#include "storage_manager.h"
#include "cdrLang.h"
#include "passwd_util.h"
#include "wallet_adapter.h"
#include "resource.h"
#include "wallet_adapter.h"
#include "libddi.h"
#include "TxShowWin.h"
#include "cdr_widgets.h"
#include "qr_pack.h"
#include "ex_bt.h"
#include "GuideWin.h"
#include "ex_charge.h"
#include "wallet_proto_qr.h"
#include "gui_icons.h"
#include "gui_statusbar.h"
#include "secure_util.h"
#include "cmaths.h"
#include "dynamic_win.h"
#include "rand.h"

ProtoClientMessage *mMessage = NULL;

static char mClientName[32] = {0};

static tips_st mTips[] = {
        {QR_DECODE_ACCOUNT_MISMATCH,      "Error", NULL},
        {QR_DECODE_UNSUPPORT_MSG,         "Error", NULL},

        {PROC_ERROR_COIN_ALL_NOT_SUPPORT, "Add Coin", "Some coins are unsupported. Update X1 and try again."},

        {QR_MSG_GET_PUBKEY_REQUEST,       "Add Coin", "Add successfully."},
        {QR_MSG_USER_ACTIVE,              "Active",   "Active successfully."},
};

static const uint8_t BIND_SK[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static tips_st *get_tips(int code) {
    int i = 0;

    for (i = 0; i < ARRAY_SIZE(mTips); i++) {
        if (code == mTips[i].code) {
            if (code == QR_DECODE_ACCOUNT_MISMATCH) {
                mTips[i].title = res_getLabel(LANG_LABEL_ALERT);
                mTips[i].msg = res_getLabel(LANG_LABEL_ACCOUNT_MISMATCH);
            } else if (code == QR_DECODE_UNSUPPORT_MSG) {
                mTips[i].title = res_getLabel(LANG_LABEL_ALERT);
                mTips[i].msg = res_getLabel(LANG_LABEL_UNSUPPORT_MSG);
            } else if (code == QR_MSG_USER_ACTIVE) {
                mTips[i].title = res_getLabel(LANG_LABEL_USER_ACTIVE_TITLE);
                mTips[i].msg = res_getLabel(LANG_LABEL_USER_ACTIVE_SUCCESS_TIPS);
            } else if (code == QR_MSG_GET_PUBKEY_REQUEST) {
                mTips[i].title = res_getLabel(LANG_LABEL_ADD_COIN_TITLE);
                mTips[i].msg = res_getLabel(LANG_LABEL_ADD_COIN_SUCCESS);
            } else if (code == PROC_ERROR_COIN_ALL_NOT_SUPPORT) {
                mTips[i].title = res_getLabel(LANG_LABEL_ADD_COIN_TITLE);
                mTips[i].msg = res_getLabel(LANG_LABEL_ADD_COIN_UNSUPPORT_TIPS);
            }

            return &mTips[i];
        }
    }

    return NULL;
}

static int check_client_uniq_id(const char *client_unique_id) {
    if (is_empty_string(client_unique_id)) {
        db_error("empty uniqid");
        return -1;
    }
    size_t len = strlen(client_unique_id);
    if (len > CLIENT_UNIQID_MAX_LEN) {
        db_error("too long uniqid:%d -> %s", len, client_unique_id);
        return -2;
    }
    if (strchr(client_unique_id, '\'')) {
        db_error("invalid char uniqid:%d -> %s", len, client_unique_id);
        return -3;
    }
    return 0;
}

int genDeviceInfo(struct pbc_wmessage *device, int type) {
    char tmpbuf[128];
    memset(tmpbuf, 0, sizeof(tmpbuf));
    int ret = device_get_id(tmpbuf, 32);
    db_msg("deviceid:%d -> %s", ret, tmpbuf);
    pbc_wmessage_string(device, "id", tmpbuf, 0);

    memset(tmpbuf, 0, 32);
    get_device_name(tmpbuf, 32, 0);
    db_msg("name:%s", tmpbuf);
    pbc_wmessage_string(device, "name", tmpbuf, 0);

    memset(tmpbuf, 0, 32);
    if (wallet_getAccountSuffix(tmpbuf) > 0) {
        pbc_wmessage_string(device, "account_suffix", tmpbuf, 0);
    }

    pbc_wmessage_integer(device, "version", DEVICE_APP_INT_VERSION, 0);
    pbc_wmessage_integer(device, "se_version", SECHIP_APP_VERSION, 0);

    if (type == 0) {
        memset(tmpbuf, 0, 32);
        device_get_sn(tmpbuf, 32);
        pbc_wmessage_string(device, "product_sn", tmpbuf, 0);
        pbc_wmessage_string(device, "product_series", PRODUCT_SERIES_VALUE, 0);
        pbc_wmessage_string(device, "product_type", PRODUCT_TYPE_VALUE, 0);
        pbc_wmessage_string(device, "product_name", PRODUCT_NAME_VALUE, 0);
        pbc_wmessage_string(device, "product_brand", PRODUCT_BRAND_VALUE, 0);
        UserActiveInfo info;
        if (device_get_user_active_info(&info) == 0) {
            pbc_wmessage_integer(device, "active_time", (uint32_t) info.time, 0);
            pbc_wmessage_integer(device, "active_time_zone", (uint32_t) info.time_zone, 0);
        }
    }
    return 0;
}

int genPubHDNode(struct pbc_wmessage *wmsg, const CoinInfo *info, unsigned char passhash[PASSWD_HASHED_LEN]) {
    int ret = get_coin_pubkey_wmsg(wmsg, info, passhash);
    if (ret == 0) {
        //save in coins db
        storage_save_coin(info->type, info->uname);
    }
    return ret;
}

int syncAllCoins(struct pbc_wmessage *wmsg, unsigned char passhash[PASSWD_HASHED_LEN], struct pbc_rmessage *req) {
    int ret;
    if (gSettings->mCoinsVersion < COINS_INIT_VERSION) {
        //loading_win_start(0, "", NULL, 0);
        wallet_initDefaultCoin(passhash);
        //loading_win_stop();
    }

    int count = storage_getCoinsCount(0);
    db_msg("coins count:%d", count);
    if (count == 0) {
        //loading_win_start(0, "", NULL, 0);
        wallet_initDefaultCoin(passhash);
        //loading_win_stop();
        count = storage_getCoinsCount(0);
        db_msg("after init coins count:%d", count);
    }
    if (count < 1) {
        dialog_error3(0, -201, "Pair failed.");
        return 0;
    }
    int coin_number = pbc_rmessage_size(req, "coin");
    db_msg("coin_number:%d", coin_number);
    unsigned long clock = getMsClockTime();
    unsigned long clock2;
    if (coin_number > 0) {
        CoinInfo qinfo;
        int newc = 0;
        int coin_yes = 0;
        int coin_no = 0;
        for (int i = 0; i < coin_number; i++) {
            memset(&qinfo, 0, sizeof(qinfo));
            if (proto_rmsg_CoinInfo(req, &qinfo, "coin", i) != 0) {
                db_error("get coin info false");
                break;
            }
            if (coin_is_real_coin(qinfo.type, qinfo.uname)) {
                coin_yes++;
                if (!storage_isCoinExist(qinfo.type, qinfo.uname)) {
                    if (!newc) {
                        //loading_win_start(0, "", NULL, 0);
                        clock = getMsClockTime();
                    }
                    newc++;
                    wallet_genDefaultPubHDNode(passhash, qinfo.type, qinfo.uname);
                    clock2 = getMsClockTime();
                    if (clock2 > (clock + 100)) {
                        clock = clock2;
                        loading_win_refresh();
                    }
                }
            } else {
                coin_no++;
            }
        }
        if (newc) {
            //loading_win_stop();
            count = storage_getCoinsCount(0);
            db_msg("after dsync add count:%d", count);
            if (count < 1) {
                dialog_error3(0, -202, "Pair failed.");
                return 0;
            }
        }
        if (coin_no) {
            //picDialog(0, "coin_some_not_supported", res_getLabel(LANG_LABEL_TXT_OK), NULL, 0);
        }
    }

    int oknum = 0;
    int errnum = 0;
    DBCoinInfo coin;
    CoinInfo qinfo;
    for (int i = 0; i < count; i++) {
        memset(&coin, 0, sizeof(DBCoinInfo));
        memset(&qinfo, 0, sizeof(qinfo));
        if (storage_queryCoinInfo(&coin, 1, i, 0) != 1) {
            break;
        }
        if (!coin_is_real_coin(coin.type, coin.uname)) {
            db_msg("skip not real coin:%d %s", coin.type, coin.uname);
            continue;
        }
        qinfo.type = coin.type;
        qinfo.uname = coin.uname;
        uint16_t curv = coin_get_curv_id(qinfo.type, qinfo.uname);
        ret = genPubHDNode(wmsg, &qinfo, passhash);
        if (ret != 0) {
            errnum++;
        } else {
            oknum++;
        }
    }

    if (errnum) {
        if (oknum) {
            dialog_error3(0, -(10000 + errnum), "Pair failed.");
        } else {
            dialog_error3(0, -(20000 + errnum), "Pair failed.");
        }
    }
    return 0;
}

int confirmBindAccount(void) {
    db_msg("start");
    int client_id;
    curve_point pub;

    int ret, rst = -100;
    char tmpbuf[256], seckey_random[65] = {0};
    const ecdsa_curve *curve = &secp256k1;
    int isBack = 0;
    int err = 0;

    BindAccountReq req;
    if (proto_rmsg_BindAccountReq(mMessage->rmsg, &req) != 0) {
        db_error("decode BindAccountReq false");
        return -1;
    }

    const char *client_unique_id = req.client_unique_id;
    const char *client_name = req.client_name;
    const unsigned char *sec_random = req.sec_random.bytes;
    int bind_version = req.version;
    int resp_version = 0x1;
    db_msg("req bind_version:%d client_unique_id:%s client_name:%s random:%d -> %s", bind_version, client_unique_id,
           client_name,
           req.sec_random.size, debug_ubin_to_hex(sec_random, req.sec_random.size));

    int errcode = 0;
    if (is_empty_string(client_name)) { //invalid req
        errcode |= 0x1;
    }
    if (check_client_uniq_id(client_unique_id) != 0) {
        errcode |= 0x2;
    }
    if ((req.sec_random.size == 65 && sec_random[0] == 0x4) ||
        (req.sec_random.size == 33 && (sec_random[0] == 0x2 || sec_random[0] == 0x3))) {
        ret = ecdsa_read_pubkey(curve, sec_random, &pub);
        if (ret != 1) {
            db_error("invalid random pubkey");
            errcode |= 0x8;
        }
    } else {
        errcode |= 0x4;
    }

    if (bind_version < 1) {
        errcode |= 0x10;
    }

    if (errcode) {
        db_error("invalid request errcode:%d", errcode);
        dialog_error3(0, errcode, "Pair failed.");
        return 0;
    }

    struct pbc_wmessage *wmsg = NULL;
    struct pbc_wmessage *wmsg_wrapper = NULL;
    unsigned char passhash[PASSWD_HASHED_LEN] = {0};

    do {
        ret = gui_disp_info(res_getLabel(LANG_LABEL_BIND_WALLET),
                            res_getLabel(LANG_LABEL_CONFIRM_BIND_WALLET), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                            res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
        db_msg("dialog_confirm ret:%d", ret);
        if (ret == EVENT_CANCEL) {
            ret = KEY_EVENT_ABORT;
            isBack = 1;
            break;
        } else if (ret == EVENT_ERROR || ret == EVENT_TIMEOUT) {
            ret = -1;
            err = 1;
            break;
        } else if (ret == EVENT_KEY_F1) {
            ret = RETURN_DISP_MAINPANEL;
            isBack = 1;
            break;
        }
        ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_PASSWD), PIN_CODE_VERITY, passhash, 1);
        //ddi_bt_ioctl(DDI_BT_CTL_BLE_CLEAR_FIFO, 0, 0);
        if (ret == KEY_EVENT_ABORT) {
            continue;
        } else if (ret < 0 || ret == RETURN_DISP_MAINPANEL) {
            memzero(passhash, PASSWD_HASHED_LEN);
            db_error("input passwd ret:%d", ret);
            err = 1;
            break;
        } else {
            loading_win_start(0, res_getLabel(LANG_LABEL_BIND_WALLET), NULL, 0);
            break;
        }
    } while (1);
    if (err || isBack) {
        //changeWindow(WINDOWID_MAINPANEL);
        return ret;
    }

    do {
        ClientInfo client;
        memset(&client, 0, sizeof(ClientInfo));
        client_id = storage_queryClientId(client_unique_id);
        if (client_id > 0) {
            db_error("unique_id:%s have binded client_id:%d", client_unique_id, client_id);
            if (storage_getClientInfo(client_id, &client) != 0) {
                db_error("get client info false client_id:%d", client_id);
                memset(&client, 0, sizeof(ClientInfo));
                client_id = 0;
            }
        } else {
            client_id = 0;
        }
        SHA256_CTX context;
        sha256_Init(&context);
        sha256_Update(&context, req.sec_random.bytes, req.sec_random.size);
        sha256_Update(&context, client_unique_id, strlen(client_unique_id));

        unsigned char myrandkey[32];
        unsigned char *seckey = myrandkey; //reuse buffer
        bignum256 k;
        memset(myrandkey, 0, sizeof(myrandkey));
        memset(tmpbuf, 0, sizeof(tmpbuf));
        ret = device_get_pub_cpuid(tmpbuf, sizeof(tmpbuf));
        if (ret > 32) { //error device ??
            tmpbuf[32] = 0;
        }
        char salt[] = {
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0};
        XDEFINE_STRING(salt);
        strcat(tmpbuf, salt);
        strcat(tmpbuf, client_unique_id);
        ret = strlen(tmpbuf);
        db_debug("myrandkey init buffer:%d -> %s", ret, tmpbuf);
        sha256_Raw((const uint8_t *) tmpbuf, (size_t) ret, myrandkey);
        db_debug("myrandkey R1:%s", debug_ubin_to_hex(myrandkey, 32));
        do {
            sha256_Raw(myrandkey, sizeof(myrandkey), myrandkey);
            db_debug("myrandkey:%s", debug_ubin_to_hex(myrandkey, 32));
            bn_read_be(myrandkey, &k);
        } while (bn_is_zero(&k) || !bn_is_less(&k, &curve->order));

        // compute k*pub -> pub
        point_multiply(curve, &k, &pub, &pub);
        memset(seckey, 0, 32);
        bn_write_be(&pub.x, seckey);
        sha256_Update(&context, seckey, 32);

        if (client_id > 0 && memcmp(client.seckey, seckey, 32) == 0) {
            db_msg("same seckey:%s old clientid:%d", debug_ubin_to_hex(seckey, 32), client_id);
        } else {
            db_msg("new seckey:%s new client time:%d time_zone:%d", debug_ubin_to_hex(seckey, 32), mMessage->time,
                   mMessage->time_zone);
            memcpy(client.seckey, seckey, 32);
            client.bind_time = mMessage->time + mMessage->time_zone;
            strncpy(client.unique_id, client_unique_id, CLIENT_UNIQID_MAX_LEN);
            strncpy(client.client_name, client_name, CLIENT_NAME_MAX_LEN);
            client_id = storage_saveClientInfo(&client);
            if (client_id <= 0) {
                db_error("save client error ret:%d", client_id);
                if (client_id == SM_ERROR_TOO_MUCH_CLIENT) {
                    dialog_error3(0, client_id, "Pair failed.");
                    break;
                } else {
                    break;
                }
            }
        }

        //gen my curve_point
        // compute k*G -> R
        unsigned char *seckeybuff = (unsigned char *) seckey_random; //reuse tmpbuf
        point_multiply(curve, &k, &curve->G, &pub);
        seckeybuff[0] = 4;
        bn_write_be(&pub.x, seckeybuff + 1);
        bn_write_be(&pub.y, seckeybuff + 33);

        db_msg("my pubkey:%s", debug_ubin_to_hex(seckeybuff, 65));

        wmsg = proto_new_wmessage("Wallet.BindAccountResp");
        if (!wmsg) {
            break;
        }
        if (bind_version > 0) {
            wmsg_wrapper = proto_new_wmessage("Wallet.BindAccountRespWrapper");
        } else {
            wmsg_wrapper = wmsg;
        }

        pbc_wmessage_string(wmsg_wrapper, "client_unique_id", client_unique_id, 0);
        pbc_wmessage_integer(wmsg, "client_id", (uint32_t) client_id, 0);
        pbc_wmessage_string(wmsg_wrapper, "sec_random", (const char *) seckeybuff, 65);
        sha256_Update(&context, seckeybuff, 65);

        struct pbc_wmessage *device = pbc_wmessage_message(wmsg, "device_info");
        if (!device) {
            break;
        }
        ret = genDeviceInfo(device, 0);
        //pbc_wmessage_string(device, "active_code", "", 0);
        syncAllCoins(wmsg, passhash, mMessage->rmsg);
        // wallet_set_private_key(NULL);
        pbc_wmessage_integer(wmsg, "version", (uint32_t) resp_version, 0);
        if (wmsg_wrapper != wmsg) {
            pbc_wmessage_integer(wmsg_wrapper, "version", (uint32_t) resp_version, 0);
        }

        uint64_t account_id = wallet_AccountId();
        db_msg("account_id:%llx", account_id);
        pbc_wmessage_integer(wmsg, "account_id", (uint32_t) account_id, 0);
        if (account_id) {
            memset(tmpbuf, 0, 8);
            wallet_getAccountSuffix(tmpbuf);
            pbc_wmessage_string(wmsg, "account_suffix", tmpbuf, 0);
        }
        pbc_wmessage_integer(wmsg, "account_type", (uint32_t) gSettings->mAccountType, 0);

        struct pbc_slice result;
        pbc_wmessage_buffer(wmsg, &result);
        //MH abort
        //debug_show_long_bin_data("account qr:", (const unsigned char *) result.buffer, result.len);
        if (wmsg_wrapper != wmsg) {
            unsigned char *encode_buff = (unsigned char *) malloc(result.len);
            if (!encode_buff) {
                break;
            }
            unsigned char *digest = myrandkey; //reuse
            sha256_Raw((const unsigned char *) result.buffer, result.len, digest);
            if (aes256_encrypt((const unsigned char *) result.buffer, encode_buff, result.len, client.seckey) != 0) {
                free(encode_buff);
                break;
            }
            pbc_wmessage_string(wmsg_wrapper, "encoded_info", (const char *) encode_buff, result.len);
            pbc_wmessage_string(wmsg_wrapper, "encoded_digest", (const char *) digest, 8);
            sha256_Update(&context, encode_buff, result.len);
            free(encode_buff);

            sha256_Final(&context, digest);
            db_msg("digest:%s", debug_bin_to_hex(digest, 32));
            memset(tmpbuf, 0, 128);
            uint8_t *sk = (uint8_t *) (tmpbuf + 80);
            XDEFINE_BUFFER2(sk, 32, BIND_SK);
            ret = ecdsa_sign_digest(&secp256k1, sk, digest, (uint8_t *) tmpbuf, NULL, NULL);
            if (ret != 0) {
                db_error("invalid sk_enc ret:%d", ret);
                break;
            }
            pbc_wmessage_string(wmsg_wrapper, "sec_random_signature", (const char *) tmpbuf, 64);
            pbc_wmessage_buffer(wmsg_wrapper, &result);
        }
        memset(&client, 0, sizeof(ClientInfo)); //clean it
        rst = showQRWindow(0, 0, mMessage->flag, QR_MSG_BIND_ACCOUNT_RESP, (const unsigned char *) result.buffer,
                           result.len);
    } while (0);
    db_msg("done clean bufer");
    memzero(passhash, PASSWD_HASHED_LEN);
    memzero(tmpbuf, sizeof(tmpbuf));
    memzero(seckey_random, sizeof(seckey_random));
    if (wmsg) {
        proto_delete_wmessage(wmsg);
        if (wmsg_wrapper && wmsg_wrapper != wmsg) {
            proto_delete_wmessage(wmsg_wrapper);
        }
    }
    //changeWindow(WINDOWID_MAINPANEL);
    if (rst == 0) {
        return PROC_WITHOUT_RSP;
    }

    return rst;
}

int confirmGetPubkey(void) {
    db_msg("confirmGetPubkey start");
    struct pbc_rmessage *req = mMessage->rmsg;
    int coin_number = pbc_rmessage_size(req, "coin");
    if (coin_number < 1) {
        db_error("invalid coin size:%d", coin_number);
        return -1;
    }

    struct pbc_wmessage *wmsg = proto_new_wmessage("Wallet.GetPubkeyResp");
    if (!wmsg) {
        db_error("proto new wmessage failed");
        return 0;
    }

    unsigned char passhash[PASSWD_HASHED_LEN] = {0};
    int ret = 0;
    do {
        ret = passwdKeyboard(0, res_getLabel(LANG_LABEL_ENTER_PASSWD), PIN_CODE_VERITY, passhash, 1);
        if (ret == USER_PASSWD_ERR_ABORT) {
            ret = gui_disp_info(res_getLabel(LANG_LABEL_CANCEL), res_getLabel(LANG_LABEL_CANCEL_ADD_COIN), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_CANCEL), res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_NONE);
            if (ret != EVENT_CANCEL) {
                proto_delete_wmessage(wmsg);
                return USER_PASSWD_ERR_ABORT;
            } else {
                continue;
            }
        } else if (ret < 0 || ret == RETURN_DISP_MAINPANEL) {
            db_error("input passwd ret:%d", ret);
            proto_delete_wmessage(wmsg);
            if (gHaveSeed) {
                //changeWindow(WINDOWID_MAINPANEL);
            }
            return ret;
        } else {
            break;
        }
    } while (1);

    CoinInfo qinfo;
    int oknum = 0;
    int errnum = 0;
    int i = 0;
    long long clock = getMsClockTime();
    long long clock2;
    loading_win_start(0, "", NULL, 0);
    db_msg("coin_number:%d", coin_number);
    for (; i < coin_number; i++) {
        memset(&qinfo, 0, sizeof(qinfo));
        if (proto_rmsg_CoinInfo(req, &qinfo, "coin", i) != 0) {
            db_error("get coin info false");
            break;
        }
        db_msg("qinfo type:%d uname:%s", qinfo.type, qinfo.uname);
        if (qinfo.type == COIN_TYPE_EOS) {
            errnum++;
            continue;
        }
        uint16_t curv = coin_get_curv_id(qinfo.type, qinfo.uname);
        ret = genPubHDNode(wmsg, &qinfo, passhash);
        if (ret != 0) {
            errnum++;
        } else {
            oknum++;
        }
        clock2 = getMsClockTime();
        if (clock2 > (clock + 100)) {
            clock = clock2;
            loading_win_refresh();
        }
    }
    loading_win_stop();
    memzero(passhash, PASSWD_HASHED_LEN);
    if (!oknum) { //all false
        db_error("gen node false i:%d total:%d", i, coin_number);
        proto_delete_wmessage(wmsg);
        //changeWindow(WINDOWID_MAINPANEL);
        respCommonNotify(DEVICE_NOT_SUPPORT);
        return PROC_ERROR_COIN_ALL_NOT_SUPPORT;
    } else if (errnum) { //some false
        ret = gui_disp_info(res_getLabel(LANG_LABEL_ADD_COIN_TITLE), res_getLabel(LANG_LABEL_ADD_COIN_UNSUPPORT_TIPS),
                            TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
        if (ret == EVENT_CANCEL) {
            proto_delete_wmessage(wmsg);
            respCommonNotify(DEVICE_NOT_SUPPORT);
            return PROC_WITHOUT_RSP;
        } else if (ret == EVENT_KEY_F1) {
            proto_delete_wmessage(wmsg);
            return RETURN_DISP_MAINPANEL;
        }
    }
    struct pbc_wmessage *device = pbc_wmessage_message(wmsg, "device_info");
    if (device) {
        genDeviceInfo(device, 1);
    }
    struct pbc_slice result;
    pbc_wmessage_buffer(wmsg, &result);
    int rst = -1;
    rst = showQRWindow(0, mMessage->client_id, mMessage->flag, QR_MSG_GET_PUBKEY_RESP,
                       (const unsigned char *) result.buffer, result.len);
    proto_delete_wmessage(wmsg);
    //changeWindow(WINDOWID_MAINPANEL);
    db_debug("confirmGetPubkey rst:%d", rst);
    return rst;
}

void active_show_time_cb(uint8_t *str, uint32_t len) {
    if (str == NULL) {
        return;
    }

    int atime = device_get_active_time();
    db_msg("atime:%d", atime);
    format_time(str, len, atime, 0, 2);
}

int procUserActive(activeDeviceReq *req) {
    if (!mMessage || !mMessage->data || mMessage->data->len < sizeof(user_active_info)) {
        db_error("invalid request");
        return -1;
    }
#ifdef DEBUG_ON
    s_printhex("req->data.bytes", req->data.bytes, req->data.size);
#endif
    if (memcmp(req->data.bytes, "UA:", 3) != 0) {//0x55 41 3a
        db_error("invalid request");
        return -1;
    }
    user_active_info info;
    int ret = 0;
    //loading_win_start(0, "", NULL, 0);
    if (active_decode_info(&info, (const unsigned char *) (req->data.bytes + 3), req->data.size - 3) != 0) {
        db_error("decode active info false");
        loading_win_stop();
        return 0;
    }
    //loading_win_refresh();
    ret = device_user_active((UserActiveInfo *) &info, 1);
    if (ret != 0) {
        db_debug("device user active ret:%d", ret);
        return -1;
    }
    //loading_win_stop();

    //changeWindow(WINDOWID_GUIDE);
    return 0;
}

int procDeviceState(void) {
    if (!mMessage) {
        db_error("invalid request");
        return -1;
    }

    DeviceStateReq req;
    if (proto_rmsg_DeviceStateReq(mMessage->rmsg, &req) != 0) {
        db_error("decode DeviceStateReq false");
        return -2;
    }

    db_msg("client_name:%s", req.client_name);
    db_msg("client_version:%d", req.client_version);
    db_msg("mtu:%d", req.mtu);

    Global_Ble_Mtu = req.mtu;
    memzero(mClientName, sizeof(mClientName));
    strncpy(mClientName, req.client_name, sizeof(mClientName));

    struct pbc_wmessage *wmsg = NULL;
    wmsg = proto_new_wmessage("Bluetooth.BleDeviceStateRespone");
    if (!wmsg) {
        db_error("invalid wmsg");
        return -3;
    }

    pbc_wmessage_integer(wmsg, "version", DEVICE_APP_INT_VERSION, 0);

    if (device_get_active_time() == 0) {
        pbc_wmessage_integer(wmsg, "activation", 0, 0);
    } else {
        pbc_wmessage_integer(wmsg, "activation", 1, 0);
    }

    db_msg("gSettings->mAccountType:%d", gSettings->mAccountType);
    pbc_wmessage_integer(wmsg, "account_type", (uint32_t) gSettings->mAccountType, 0);

    struct pbc_slice slice;
    int ret = 0;
    pbc_wmessage_buffer(wmsg, &slice);
    db_msg("result sz:%d flag:%d", slice.len, mMessage->flag);
    ret = showQRWindow(0, 0, 0, QR_MSG_BLE_DEVICE_STATE_RESP, (const unsigned char *) slice.buffer, (int) slice.len);
    if (ret < 0) {
        db_error("show msg:%d false,ret:%d", QR_MSG_BLE_DEVICE_STATE_RESP, ret);
        //return ret;
    }
    proto_delete_wmessage(wmsg);
    Global_Ble_Process_Step = STAT_BLE_STEP_6;
    return PROC_WITHOUT_RSP;
}

int BtProcWin(void) {
    int ret = 1;

    if (!mMessage) {
        db_error("msg is NULL");
        return -1;
    }
    gProcessing = 1;
    switch (mMessage->type) {
        case QR_MSG_BIND_ACCOUNT_REQUEST:
            ret = confirmBindAccount();
            break;
        case QR_MSG_GET_PUBKEY_REQUEST:
            ret = confirmGetPubkey();
            break;
        case QR_MSG_FACTORY_INIT:
            ret = procFactoryInit();
            break;
        case QR_MSG_BLE_DEVICE_STATE_REQUEST:
            ret = procDeviceState();
            break;
        default:
            db_error("unkown msg:%d", mMessage->type);
            return -2;
    }
    gProcessing = 0;
    db_msg("proce ret:%d", ret);

    return ret;
}

int procFactoryInit(void) {
    if (!mMessage) {
        db_error("invalid mMessage");
        return -1;
    }
    if (!mMessage->data) {
        db_error("invalid mMessage->data");
        return -1;
    }
    //............
    pvtAfterActive();
    return 0;
}

int btProcInit(ProtoClientMessage *msg) {
    if (mMessage != NULL) {
        proto_client_message_delete(mMessage);
        mMessage = NULL;
    }
    mMessage = msg;
    db_msg("type:0x%02X client:%d", msg->type, msg->client_id);
    return 0;
}

int btProcDeInit(void) {
    if (mMessage != NULL) {
        proto_client_message_delete(mMessage);
        mMessage = NULL;
    }
    return 0;
}

int procResponeNotify(int type, int code, qr_packet_header_info *h) {
    struct pbc_wmessage *wmsg = NULL;
    wmsg = proto_new_wmessage("Bluetooth.BleDeviceProcNotify");
    if (!wmsg) {
        db_error("invalid wmsg");
        return -2;
    }

    if (type != DEVICE_NOTIFY_COMMON_TYPE && type != DEVICE_NOTIFY_PACKET_TYPE) {
        db_error("invalid type:%d", type);
        return -3;
    }

    pbc_wmessage_uint32(wmsg, "notify_type", type);
    if (type == DEVICE_NOTIFY_PACKET_TYPE) {
        db_msg("h->type:%x", h->type);
        pbc_wmessage_uint32(wmsg, "message_type", h->type);
    }

    struct pbc_wmessage *wmsg_ack = pbc_wmessage_message(wmsg, "packet_ack");
    if (!wmsg_ack) {
        db_error("invalid wmsg_ack");
        proto_delete_wmessage(wmsg);
        return -4;
    }

    if (type == DEVICE_NOTIFY_PACKET_TYPE) {
        if (!h) {
            db_error("invalid h");
            return -5;
        }
        db_msg("result:%d, total:%d, index:%d", code, h->p_total, h->p_index);
        db_msg("check_code:%s", debug_bin_to_hex(h->checkcode, 4));
        pbc_wmessage_integer(wmsg_ack, "result", code > 0 ? 0 : code, 0);
        pbc_wmessage_uint32(wmsg_ack, "total", h->p_total);
        pbc_wmessage_uint32(wmsg_ack, "index", h->p_index);
        pbc_wmessage_string(wmsg_ack, "check_code", h->checkcode, 4);
    } else {
        db_msg("code:%d", code);
        memzero(mClientName, sizeof(mClientName));
        pbc_wmessage_integer(wmsg, "code", code, 0);
    }

    struct pbc_slice slice;
    int ret = 0;
    pbc_wmessage_buffer(wmsg, &slice);
    db_msg("slice.len:%d", slice.len);
    uint8_t *pbuf = malloc(slice.len + 4);
    if (pbuf == NULL) {
        proto_delete_wmessage(wmsg);
        return -3;
    }
    pbuf[0] = 0x43;
    pbuf[1] = 0x3a;
    pbuf[2] = (uint8_t) ((slice.len >> 8) & 0x000000ff);
    pbuf[3] = (uint8_t) ((slice.len >> 0) & 0x000000ff);
    memcpy(pbuf + 4, slice.buffer, slice.len);
    db_msg("notify:%s", debug_bin_to_hex(pbuf, slice.len + 4));
    ret = ddi_bt_write((const unsigned char *) pbuf, (int) slice.len + 4);
    if (ret < 0) {
        proto_delete_wmessage(wmsg);
        free(pbuf);
        db_error("code:%d, ret:%d", code, ret);
        return ret;
    }

    proto_delete_wmessage(wmsg);
    free(pbuf);

    return 0;
}

int procActiveDevice(void) {
    activeDeviceReq req;
    uint32_t urlLen = 0;
    uint8_t buff[128] = {0};
    int ret = 0;

    if (proto_rmsg_activeDeviceReq(mMessage->rmsg, &req) != 0) {
        db_error("decode DeviceStateReq false");
        return -1;
    }

    if (req.type == DEVICE_ACTIVE_REQUEST_URL) {
        loading_win_start(0, res_getLabel(LANG_LABEL_USER_ACTIVE_TITLE), res_getLabel(LANG_LABEL_ACTIVATING), 0);
        urlLen = active_get_url(buff, 128);
        loading_win_stop();
        db_msg("active_get_url ret:%d", urlLen);
        if (urlLen <= 0) {
            db_error("invalid url urlLen:%d", urlLen);
            return -3;
        }
    } else if (req.type == DEVICE_ACTIVE_REQUEST_DATA) {
        ret = procUserActive(&req);
        if (ret != 0) {
            db_error("invalid active info ret:%d", ret);
            return -3;
        }
    } else {
        db_error("invalid req.type:%d", req.type);
        return -4;
    }

    struct pbc_wmessage *wmsg = NULL;
    wmsg = proto_new_wmessage("Bluetooth.BleDeviceActiveResponse");
    if (!wmsg) {
        db_error("invalid wmsg");
        return -5;
    }
    pbc_wmessage_integer(wmsg, "type", req.type, 0);
    pbc_wmessage_integer(wmsg, "code", 0, 0);
    pbc_wmessage_string(wmsg, "result", (const char *) buff, urlLen);
    struct pbc_slice slice;
    pbc_wmessage_buffer(wmsg, &slice);
    db_msg("result sz:%d flag:%d", slice.len, 0);
    showQRWindow(0, 0, 0, QR_MSG_BLE_DEVICE_ACTIVE_RESP, (const unsigned char *) slice.buffer, (int) slice.len);
    proto_delete_wmessage(wmsg);

    return req.type;
}

static char mWalletname[32];

void dispMainPanel(int page) {
    st_bt_info bt_flash_info;
    int x0 = 0, y0 = 0, width = 0;
    strRect rect;
    char mBleName[16] = "Unknown";
    const char *tips = NULL;
    const unsigned char *pImage = NULL;
    const unsigned char *pImage_left = NULL;
    const unsigned char *pImage_right = NULL;

    if (page < 0 || page > 2) {
        page = 0;
    }

    if (page == 0) {
        memset(&bt_flash_info, 0x0, sizeof(st_bt_info));
        ddi_flash_read(YC_INFOR_ADDR, (uint8_t *) &bt_flash_info, sizeof(bt_flash_info));
        if ((bt_flash_info.flag == BT_INFOR_FLAG) && (!is_empty_string(bt_flash_info.ble_name))) {
            memset(mBleName, 0x0, sizeof(mBleName));
            memcpy(mBleName, bt_flash_info.ble_name, sizeof(bt_flash_info.ble_name));
        }
        pImage_left = gImage_setting14;
        int ble_status = ddi_bt_get_status();
        if (ble_status == BT_STATUS_CONNECTED) {
            pImage = gImage_x130connecting;
        } else {
            pImage = gImage_x130;
        }
        pImage_right = gImage_wallet14;
        tips = mBleName;
    } else if (page == 1) {
        pImage_left = gImage_x114;
        pImage = gImage_wallet30;
        pImage_right = gImage_setting14;
        tips = res_getLabel(LANG_LABEL_ASSETS);
    } else {
        pImage_left = gImage_wallet14;
        pImage = gImage_setting30;
        pImage_right = gImage_x114;
        tips = res_getLabel(LANG_LABEL_SET_TITLE);
    }

    memset(mWalletname, 0x0, sizeof(mWalletname));
    get_device_name(mWalletname, sizeof(mWalletname), 1);
    gui_creat_win(mWalletname, NULL, NULL);

    rect.m_x0 = 14;
    rect.m_x1 = rect.m_x0 + 14;
    rect.m_y0 = 28;
    rect.m_y1 = rect.m_y0 + 14;
    gui_sdk_show_image(&rect, pImage_left);

    rect.m_x0 = 100;
    rect.m_x1 = rect.m_x0 + 14;
    rect.m_y0 = 28;
    rect.m_y1 = rect.m_y0 + 14;
    gui_sdk_show_image(&rect, pImage_right);

    rect.m_x0 = 49;
    rect.m_x1 = rect.m_x0 + 30;
    rect.m_y0 = 18;
    rect.m_y1 = rect.m_y0 + 30;
    gui_sdk_show_image(&rect, pImage);

    width = ddi_lcd_get_text_width(tips);
    x0 = (g_gui_info.uiScrWidth - width) / 2;
//    db_msg("width:%d, x0:%d", width, x0);
    y0 = g_gui_info.uiScrHeight - g_gui_info.uiLineHeight;
    ddi_lcd_show_text(x0, y0, tips);

    ddi_lcd_brush_screen();
}

int dispPairCode(void) {
    uint8_t key[4] = {0}, disp[32] = {0}, str[64] = {0};
    uint32_t number = 0;
    int ret = 0, status = STAT_BT_ENCRY_STATE;

    ddi_bt_ioctl(DDI_BT_CTL_BLE_GET_CONFIRM_KEY, 0, (uint32_t) key);
    number = ((*(key + 0)) << 0) | ((*(key + 1)) << 8) | ((*(key + 2)) << 16) | ((*(key + 3)) << 24);
    if (number) {
        set_temp_screen_time(DEFAULT_MID_SCREEN_SAVER_TIME);
        db_msg("number:%d,key[0]:%x", number, key[0]);
        for (int i = 0; i < 6; i++) {
            disp[5 - i] = number % 10 + 0x30;
            number /= 10;
        }
        snprintf(str, sizeof(str), "%s:\n%s", res_getLabel(LANG_LABEL_BT_PAIRING_CODE), disp);
        ret = gui_disp_info(res_getLabel(LANG_LABEL_BT_CONNECT_TITLE), str, TEXT_ALIGN_CENTER | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                            res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
        if (ret == EVENT_OK) {
            status = STAT_BT_CONFIRM_KEY;
        } else {
            ddi_bt_disconnect();
            status = STAT_BT_INIT;
        }
    }

    return status;
}

static int showWalletDetails(void) {
    char str[128];
    int width = 0;

    dwin_init();

    int ble_status = ddi_bt_get_status();
    if (ble_status == BT_STATUS_CONNECTED) {
        memset(str, 0x0, sizeof(str));
        snprintf(str, sizeof(str), "%s:\n%s", "Connected Device", mClientName);
        SetWindowMText(0, str);
    }

    st_bt_info bt_flash_info;
    char bleName[24] = "Unknown";
    ddi_flash_read(YC_INFOR_ADDR, (uint8_t *) &bt_flash_info, sizeof(bt_flash_info));
    if ((bt_flash_info.flag == BT_INFOR_FLAG) && (!is_empty_string(bt_flash_info.ble_name))) {
        memcpy(bleName, bt_flash_info.ble_name, sizeof(bt_flash_info.ble_name));
    }

    memset(str, 0x0, sizeof(str));
    if (ble_status == BT_STATUS_CONNECTED) {
        snprintf(str, sizeof(str), "%s: %s", "BlueTooth", "Connected");
    } else {
        snprintf(str, sizeof(str), "%s:\n%s", "BlueTooth", "Not connected");
    }
    SetWindowMText(0, str);

    const char *actime_title = res_getLabel(LANG_LABEL_DEVICE_ACTIVE_TIME);
    memset(str, 0x0, sizeof(str));
    snprintf(str, sizeof(str), "%s:", actime_title);
    SetWindowMText(0, str);
    memset(str, 0x0, sizeof(str));
    int atime = device_get_active_time();
    if (atime > 100) {
        format_time(str, sizeof(str), atime, 0, 2);
    }
    SetWindowMText(0, str);

    int ret = ShowWindowTxt(bleName, TEXT_ALIGN_LEFT, res_getLabel(LANG_LABEL_BACK), res_getLabel(LANG_LABEL_SUBMENU_OK));
    dwin_destory();

    return ret;
}

static void showBleConnecting(void) {
    gui_show_state("Bluetooth", "Bluetooth is\nconnecting...");
    ddi_sys_msleep(600);
}

int mainPanel(void) {
    int status = STAT_BT_INIT, statusOld = 0, ret = 0, recvLen = 0;
    int isBrushPanel = 1, cnt = 0, notifyCnt = 0, page = 1;
    int key = 0, init = 1, datalen = 0, brushBarCnt = 1, notifyTick = 0;
    uint8_t recvBuff[800], btStatus = 0, encStatus = 0;
    uint8_t param[8] = {0x06, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x2c, 0x01};

    ddi_bt_open();

    uint8_t mode = LE_PAIRING_SEC_CONNECT_NUMERIC;
    ddi_bt_ioctl(DDI_BT_CTL_SET_BLE_PAIRING_MODE, (uint32_t) &mode, 0);

    while (1) {
        if (isBrushPanel == 1 || status != statusOld) {
            dispMainPanel(page);
            statusOld = status;
            isBrushPanel = 0;
        }

        ddi_key_read(&key);
        if (key == K_OK || key == K_2) {
            if (page == 0) ret = showWalletDetails();
            else if (page == 1) ret = CoinsWin(0);
            else if (page == 2) ret = SettingWin();
            isBrushPanel = 1;
        } else if (key == K_LEFT || key == K_CANCEL || key == K_1) {
            if (page == 0) page = 2;
            else page--;
            isBrushPanel = 1;
        } else if (key == K_RIGHT || key == K_3) {
            if (page == 2) page = 0;
            else page++;
            isBrushPanel = 1;
        }

        if ((brushBarCnt == 1) || (brushBarCnt > 35)) {
            gui_cb_check_status_bar();
            brushBarCnt = 1;
        }
        brushBarCnt++;

        switch (status) {
            case STAT_BT_INIT:
                db_msg("STAT_BT_INIT");
                set_temp_screen_time(gSettings->mScreenSaver);
                status = STAT_BT_START_PAIRING;
                Global_Ble_Process_Step = STAT_BLE_STEP_1;
                break;

            case STAT_BT_START_PAIRING:
                btStatus = ddi_bt_get_status();
                if (btStatus == BT_STATUS_CONNECTED) {
                    ret = ddi_bt_ioctl(DDI_BT_CTL_BLE_UPDATE_CONN_PARAM, (uint32_t) param, 0);
                    db_msg("update conn param ret:%d", ret);
                    status = STAT_BT_ENCRY_STATE;
                }
                break;

            case STAT_BT_ENCRY_STATE:
                ddi_bt_ioctl(DDI_BT_CTL_BLE_ENCRYPTION_STATE, 0, (uint32_t) &encStatus);
                db_msg("encStatus:%d", encStatus);
                if (encStatus == 0x01) {
                    status = STAT_DATA_RECV;
                    ddi_sys_msleep(1000);
                    ddi_sys_get_tick(&notifyTick);
                    respCommonNotify(DEVICE_READY);
                    Global_Ble_Process_Step = STAT_BLE_STEP_2;
                    notifyCnt = 0;
                    cnt = 0;
                } else {
                    cnt++;
                    if (cnt > PROC_BLE_GET_ENC_STATE_CNT) {
                        ddi_bt_ioctl(DDI_BT_CTL_BLE_START_PAIRING, 0, 0);
                        status = STAT_BT_DISP_CONFIRM_KEY;
                        cnt = 0;
                    }
                }
                break;

            case STAT_BT_DISP_CONFIRM_KEY:
                cnt = 0;
                btStatus = ddi_bt_get_status();
                if (btStatus != BT_STATUS_CONNECTED) {
                    status = STAT_BT_INIT;
                    db_msg("bt has been disconnected");
                    break;
                }
                status = dispPairCode();
                break;

            case STAT_BT_CONFIRM_KEY:
                btStatus = ddi_bt_get_status();
                if (btStatus != BT_STATUS_CONNECTED) {
                    status = STAT_BT_INIT;
                    db_msg("bt has been disconnected");
                    break;
                }
                ret = ddi_bt_ioctl(DDI_BT_CTL_BLE_CONFIRM_KEY, 0, 0);
                status = STAT_BT_GET_CONFIRM_KEY_STAT;
                break;

            case STAT_BT_GET_CONFIRM_KEY_STAT:
                ret = ddi_bt_ioctl(DDI_BT_CTL_GET_STATUS, 0, 0);
                if (ret == BT_BNEP_BLE_PAIR) {
                    status = STAT_BT_GET_ENCRY_STATE;
                    cnt = 0;
                } else {//BT_BNEP_BLE_PAIR_FAIL
                    cnt++;
                }
                btStatus = ddi_bt_get_status();
                db_msg("ret:%d, cnt:%d, btStatus:%d", ret, cnt, btStatus);
                if (cnt > PROC_BLE_CONFIRM_PAIR_STATE_CNT || btStatus != BT_STATUS_CONNECTED) {
                    gui_disp_info(res_getLabel(LANG_LABEL_BT_CONNECT_FAIL_TITLE),
                                  res_getLabel(LANG_LABEL_BT_CONNECT_FAIL_TIPS), TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER,
                                  NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    ddi_bt_disconnect();
                    status = STAT_BT_INIT;
                    cnt = 0;
                }
                break;

            case STAT_BT_GET_ENCRY_STATE:
                ddi_bt_ioctl(DDI_BT_CTL_BLE_ENCRYPTION_STATE, 0, (uint32_t) &encStatus);
                db_msg("confirm encStatus:%d", encStatus);
                if (encStatus == 0x01) {
                    status = STAT_DATA_RECV;
                    ddi_sys_get_tick(&notifyTick);
                    respCommonNotify(DEVICE_READY);
                    Global_Ble_Process_Step = STAT_BLE_STEP_2;
                    notifyCnt = 0;
                    cnt = 0;
                } else {
                    cnt++;
                    if (cnt > PROC_BLE_GET_ENC_STATE_CNT) {
                        status = STAT_DATA_RECV;
                        ddi_sys_get_tick(&notifyTick);
                        respCommonNotify(DEVICE_READY);
                        Global_Ble_Process_Step = STAT_BLE_STEP_2;
                        notifyCnt = 0;
                        cnt = 0;
                    }
                }
                break;

            case STAT_DATA_RECV:
                btStatus = ddi_bt_get_status();
                if (btStatus != BT_STATUS_CONNECTED) {
                    status = STAT_BT_INIT;
                    isBrushPanel = 1;
                    set_temp_screen_time(0);
                    db_msg("bt has been disconnected");
                    break;
                }
                memset(recvBuff, 0x0, sizeof(recvBuff));
                recvLen = onBtRecvData(recvBuff, sizeof(recvBuff));
                if (recvLen > 0) {
                    //db_msg("recvLen:%d", recvLen);
                    notifyCnt = PROC_BLE_NOTIFY_CNT;
                    if (init) {
                        BtRecvInit();
                    }
                    ret = onBtResult(recvBuff, recvLen);
                    db_msg("onBtResult ret:%d", ret);
                    qr_packet_header_info header;
                    memset(&header, 0x0, sizeof(qr_packet_header_info));
                    if (parse_qr_packet_header_info(recvBuff, recvLen, &header) == 0) {
                        procResponeNotify(DEVICE_NOTIFY_PACKET_TYPE, ret, &header);
                    }
                    init = 1;
                    if (ret < 0) {
                        status = STAT_ERR_RSP;
                        statusOld = STAT_ERR_RSP;
                        isBrushPanel = 0;
                    } else if (ret == WINDOWID_QRPROC) {
                        status = STAT_TRANS_PROC;
                        statusOld = STAT_TRANS_PROC;
                        isBrushPanel = 0;
                    } else if (ret == WINDOWID_TXSHOW) {
                        status = STAT_TRANS_SIGN;
                        statusOld = STAT_TRANS_SIGN;
                        isBrushPanel = 0;
                    } else if (ret == QR_GET_MULTI_PACKETS) {
                        init = 0;
                    }
                } else if (recvLen == KEY_EVENT_ABORT) {
                    isBrushPanel = 1;
                } else {
                    if (notifyCnt < PROC_BLE_NOTIFY_CNT) {
                        if (ddi_utils_stimer_query(notifyTick, (notifyCnt + 1) * 2000)) {
                            db_msg("procResponeNotify notifyCnt:%d", notifyCnt);
                            respCommonNotify(DEVICE_READY);
                            ddi_sys_get_tick(&notifyTick);
                            notifyCnt++;
                            Global_Ble_Process_Step = STAT_BLE_STEP_2 + notifyCnt;
                        }
                    }
                }
                break;

            case STAT_TRANS_PROC:
                set_temp_screen_time(DEFAULT_MID_SCREEN_SAVER_TIME);
                ret = BtProcWin();
                if (ret == 0) {
                    tips_st *tips = get_tips(mMessage->type);
                    if (!tips) {
                        dialog_error4(ret, res_getLabel(LANG_LABEL_TX_OK_TITLE), res_getLabel(LANG_LABEL_TX_OK_TIPS));
                    } else {
                        gui_disp_info(tips->title, tips->msg, TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL,
                                      res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    }
                    status = STAT_DATA_RECV;
                } else if (ret == PROC_WITHOUT_RSP || ret == RETURN_DISP_MAINPANEL) {
                    status = STAT_DATA_RECV;
                    isBrushPanel = 1;
                } else if (ret == PROC_OTA_INFO_RSP) {
                    status = STAT_DATA_RECV;
                    statusOld = STAT_DATA_RECV;
                    isBrushPanel = 0;
                } else if (ret == KEY_EVENT_ABORT) {
                    respCommonNotify(DEVICE_USER_CANCEL);
                    status = STAT_DATA_RECV;
                    isBrushPanel = 1;
                } else {
                    status = STAT_ERR_RSP;
                    statusOld = STAT_ERR_RSP;
                    isBrushPanel = 0;
                }
                btProcDeInit();
                BtRecvDeinit();
                init = 1;
                set_temp_screen_time(gSettings->mScreenSaver);
                break;

            case STAT_TRANS_SIGN:
                set_temp_screen_time(DEFAULT_MID_SCREEN_SAVER_TIME);
                ret = TxShowWin();
                if (ret == 0) {
                    gui_disp_info(res_getLabel(LANG_LABEL_TX_OK_TITLE), res_getLabel(LANG_LABEL_TX_OK_TIPS),
                                  TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, NULL, res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    status = STAT_DATA_RECV;
                } else if (ret == KEY_EVENT_ABORT) {
                    ret = gui_disp_info(res_getLabel(LANG_LABEL_CANCEL), res_getLabel(LANG_LABEL_TX_CANCEL_TIPS),
                                        TEXT_ALIGN_LEFT | TEXT_VALIGN_CENTER, res_getLabel(LANG_LABEL_BACK),
                                        res_getLabel(LANG_LABEL_SUBMENU_OK), EVENT_KEY_F1);
                    if (ret == EVENT_CANCEL) {
                        status = STAT_TRANS_SIGN;
                        break;
                    } else {
                        respCommonNotify(DEVICE_USER_CANCEL);
                        status = STAT_DATA_RECV;
                    }
                } else if (ret == RETURN_DISP_MAINPANEL) {
                    status = STAT_DATA_RECV;
                } else {
                    status = STAT_ERR_RSP;
                }
                btProcDeInit();
                BtRecvDeinit();
                init = 1;
                set_temp_screen_time(gSettings->mScreenSaver);
                break;

            case STAT_ERR_RSP:
                BtRecvDeinit();
                status = STAT_DATA_RECV;
                isBrushPanel = 1;
                if (ret == KEY_EVENT_ABORT || ret == QR_DECODE_SYSTEM_ERR) {
                    break;
                }
                tips_st *tips = get_tips(ret);
                if (!tips) {
                    dialog_error4(ret, "Error", "System Error! Please try again.");
                } else {
                    dialog_error4(ret, tips->title, tips->msg);
                }
                break;

            default:
                status = STAT_BT_INIT;
                break;
        }

        ddi_sys_msleep(30);
    }
}	

