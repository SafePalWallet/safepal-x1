#define LOG_TAG "wallet"

#include "common.h"
#include "wallet_manager.h"
#include "wallet_proto.h"
#include "secure_api.h"
#include "bignum.h"
#include "ripemd160.h"
#include "address.h"
#include "xstr.h"
#include "device.h"
#include <aes/aes.h>
#include <secp256k1.h>
#include "coin_adapter.h"
#include "debug.h"
#include "settings.h"
#include "storage_manager.h"
#include "global.h"
#include "wallet_adapter.h"
#include "wallet_api.h"
#include "update.h"
#include "ex_types.h"
#include "wallet_manager.h"
#include "gui_api.h"

static sec_base_info mBaseInfo;
static int mInited = 0;

static int wallet_queryBaseInfo(int force);

static int wallet_cleanAccountInfo(int type);

// 0 OK 1 need OTA < 0 error
int wallet_init() {
    if (mInited) {
        memset(&mBaseInfo, 0, sizeof(sec_base_info));
    }
    int type = 0;
    int ret = sapi_init();
    if (ret == 0) {
        ret = wallet_queryBaseInfo(1);
        if (ret != 0 || !mBaseInfo.app_version) {
            db_secure("app_version:%d ret:%d", mBaseInfo.app_version, ret);
            if (!ret) ret = -11;
        } else {
            if (mBaseInfo.app_version < SECHIP_APP_VERSION) {
                db_secure("app_version:%d < %d", mBaseInfo.app_version, SECHIP_APP_VERSION);
                type = 1; // need OTA
            }
        }
    }
    mInited = 1;
    if (ret > 0) ret = -ret;
    return ret ? ret : type;
}

int wallet_isInited() {
    return mInited;
}

int wallet_queryBaseInfo(int force) {
    if (!force) {
        if (mBaseInfo.chip_type && mBaseInfo.app_version && mBaseInfo.chipid_len) { //cached
            return 0;
        }
    }
    return sapi_get_base_info(&mBaseInfo);
}

const sec_base_info *wallet_getBaseInfo() {
    if (wallet_queryBaseInfo(0) != 0) {
        return NULL;
    }
    return &mBaseInfo;
}

int wallet_getPasswdAllowErrorTimes() {
    wallet_queryBaseInfo(0);
    return mBaseInfo.max_passwd_error_times;
}

uint64_t wallet_getAccountId(int refresh) {
    if (refresh) {
        gSeedAccountId = 0;
    }
    uint64_t account_id = gSeedAccountId;
    if (!account_id) {
        account_id = sapi_get_account_id();
        if (account_id > 0) {
            gSeedAccountId = account_id; //update
        } else {
            gSeedAccountId = 0;
        }
    }
    return account_id;
}

uint64_t wallet_AccountId() {
    return gSeedAccountId ? gSeedAccountId : wallet_getAccountId(1);
}

int wallet_getAccountSuffix(char suffix[4]) {
    uint64_t id = wallet_AccountId();
    memset(suffix, 0, 4);
    if (!id) {
        return 0;
    }
    base34encode(id, suffix, 3);
    return 3;
}

//not buff
int wallet_queryPubHDNode(uint16_t curv, const char *path, const unsigned char *passwd, PubHDNode *node) {
	unsigned char bin_xpub[128] = {0};
	unsigned char rip160_digest[RIPEMD160_DIGEST_LENGTH];
	memset(node, 0, sizeof(PubHDNode));
	uint64_t account_id = wallet_AccountId();
	if (!account_id) {
		db_error("not accout id");
		return -1;
	}
	if (!IS_VALID_CURVE_TYPE(curv)) {
		db_error("invalid curv:%d", curv);
		return -1;
	}
	if (!passwd) {
		return -404;
	}
	db_msg("account id:%llx", account_id);
	int ret = sapi_get_xpub(curv, path, passwd, PASSWD_HASHED_LEN, bin_xpub, sizeof(bin_xpub));
	if (ret < 0) {
		db_error("sapi get xpub false sz:%d", ret);
		return ret;
	}
	memset(rip160_digest, 0, sizeof(rip160_digest));
	ripemd160(bin_xpub + 70, 32, rip160_digest);
	db_secure("RIPEMD160:%s", debug_ubin_to_hex(rip160_digest, RIPEMD160_DIGEST_LENGTH));
	memcpy(bin_xpub + 102, rip160_digest, 4);
	node->curve = curv;
	node->depth = bin_xpub[0];
	node->child_num = read_be(bin_xpub + 1);
	memcpy(node->chain_code, bin_xpub + 5, 32);
	memcpy(node->public_key, bin_xpub + 37, 33);
	node->fingerprint = read_be(bin_xpub + 102);
	memset(bin_xpub, 0, sizeof(bin_xpub));
	return 0;
}

int wallet_getPubHDNode(uint16_t curv, const char *path, const unsigned char *passwd, PubHDNode *node) {
	unsigned char bin_xpub[128] = {0};
	unsigned char rip160_digest[RIPEMD160_DIGEST_LENGTH];
	memset(node, 0, sizeof(PubHDNode));
	uint64_t account_id = wallet_AccountId();
	if (!account_id) {
		db_error("not accout id");
		return -1;
	}
	if (!IS_VALID_CURVE_TYPE(curv)) {
		db_error("invalid curv:%d", curv);
		return -1;
	}
	db_msg("account id:%llx", account_id);
	int ret = storage_getXpubInfo(account_id, curv, path, bin_xpub, sizeof(bin_xpub));
	if (ret <= 0) {
		if (ret < 0) {
			db_error("getXpubInfo false ret:%d", ret);
		} else {
			db_error("getXpubInfo not cached");
		}
		if (!passwd) {
			return -404;
		}
		ret = sapi_get_xpub(curv, path, passwd, PASSWD_HASHED_LEN, bin_xpub, sizeof(bin_xpub));
		if (ret < 0) {
			db_error("sapi get xpub false sz:%d", ret);
			return ret;
		}
		memset(rip160_digest, 0, sizeof(rip160_digest));
		ripemd160(bin_xpub + 70, 32, rip160_digest);
		db_secure("RIPEMD160:%s", debug_ubin_to_hex(rip160_digest, RIPEMD160_DIGEST_LENGTH));
		memcpy(bin_xpub + 102, rip160_digest, 4);
		ret = storage_saveXpubInfo(account_id, curv, path, bin_xpub, 106); // 70 + 32(raw hash256) + 4 ripemd160 digest
		if (ret < 0) {
			memset(bin_xpub, 0, sizeof(bin_xpub));
			db_error("save xpub false ret:%d", ret);
			return -1;
		}
	}
	node->curve = curv;
	node->depth = bin_xpub[0];
	node->child_num = read_be(bin_xpub + 1);
	memcpy(node->chain_code, bin_xpub + 5, 32);
	memcpy(node->public_key, bin_xpub + 37, 33);
	node->fingerprint = read_be(bin_xpub + 102);
	memset(bin_xpub, 0, sizeof(bin_xpub));
	return 0;
}

int wallet_getCoinPubHDNode(int type, const char *uname, const unsigned char *passwd, PubHDNode *node) {
    uint16_t curv = 0;
    const char *path = NULL;
    curv = coin_get_curv_id(type, uname);
    path = coin_get_hdnode_path(type, uname);
    if (!curv || is_empty_string(path)) {
        db_error("invalid type:%d uname:%s", type, uname);
        return -1;
    }
    memset(node, 0, sizeof(PubHDNode));
    int ret = wallet_getPubHDNode(curv, path, passwd, node);
    if (ret != 0) {
        db_error("get curv:%d path node:%s false", curv, path);
        return ret;
    }
    return 0;
}

// return: 1 exist; 0 not exist; other error
int wallet_check_hdnode_exist(uint16_t curv, const char *path) {
#if 0
    uint64_t account_id = wallet_AccountId();
    if (!account_id) {
        db_error("not accout id");
        return -1;
    }
    return storage_check_xpub_exist(account_id, curv, path);
#endif
    return -1;
}

int wallet_genPathPubHDNode(const unsigned char *passwd, int curv, const char *path) {
    PubHDNode pubnode;
    memset(&pubnode, 0, sizeof(PubHDNode));
    int ret = wallet_getPubHDNode(curv, path, passwd, &pubnode);
    return ret;
}

int wallet_genDefaultPubHDNode(const unsigned char *passwd, int type, const char *uname) {
	PubHDNode pubnode;
	int ret = wallet_getCoinPubHDNode(type, uname, passwd, &pubnode);
	if (ret == 0) {
		storage_save_coin(type, uname);
	}
	return ret;
}

int wallet_gen_exists_hdnode(const unsigned char *passwd, uint64_t old_account_id) {
    uint64_t account_id = wallet_AccountId();
    if (!account_id) {
        db_error("not accout id");
        return -1;
    }
    if (account_id == old_account_id) {
        db_error("same accout id:%llx", account_id);
        return 0;
    }
    cstring *data = cstr_new_sz(512);
    if (!data) {
        db_error("new cstring false");
        return -1;
    }
    int total = storage_get_xpub_exists_paths(old_account_id, data);
    db_msg("paths total:%d buff len:%d", total, data->len);
    if (total <= 0) {
        cstr_free(data);
        return -2;
    }
    loading_win_refresh();
    const char *p = (const char *) data->str;
    for (int i = 0; i < total; i++) {
        int curv = *(p + 1);
        db_msg("gen curv:%d path:%s", curv, p + 2);
        wallet_genPathPubHDNode(passwd, curv, p + 2);
        p += (*p + 1);
        loading_win_refresh();
    }
    cstr_free(data);
    return 0;
}

int wallet_initDefaultCoin(const unsigned char *passwd) {
    db_msg("init coin version:%d -> %d", gSettings->mCoinsVersion, COINS_INIT_VERSION);
    //init default xpub
    settings_save(SETTING_KEY_COINS_VERSION, COINS_INIT_VERSION);

    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_BITCOIN, "BTC");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_BITCOIN, COIN_UNAME_BTC2); //BTC bip49
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_BITCOIN, COIN_UNAME_BTC3); //BTC bip84
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_ETH, "ETH");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_BEP20, "BNB");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_TON, "TON");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_POLYGON, "MATIC");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_TRX, "TRX");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_ARBITRUM, "ARETH");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_SOLANA, "SOL");
    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_SOLANA, COIN_UNAME_SOL2);
//    wallet_genDefaultPubHDNode(passwd, COIN_TYPE_BNC, "BNB");
    return 0;
}

int wallet_cleanAccountInfo(int type) {
    db_msg("type:%d", type);
    //if (type == 1) {
    storage_cleanAllData();
#if 0
    } else {
        storage_cleanXpubs();
        storage_cleanTxs();
        storage_cleanCoinInfo();
        storage_syncData2Disk();
    }
#endif
    settings_save(SETTING_KEY_COINS_VERSION, 0);

    return 0;
}

int wallet_storeSeed(unsigned char *seed, int seedlen, const unsigned char *passwd) {
    db_secure("storeSeed");
    wallet_cleanAccountInfo(1);
    int ret = sapi_store_seed(seed, seedlen, passwd, PASSWD_HASHED_LEN);
    if (ret != 0) {
        db_serr("store seed ret:%d", ret);
        return ret;
    }
    gui_on_process(30);
    uint64_t id = wallet_getAccountId(1);
    if (!id) {
        db_serr("get account id false");
        return -41;
    }
    gui_on_process(40);
    settings_set_have_seed(id);
    gui_on_process(50);
    wallet_initDefaultCoin(passwd);
    return 0;
}

int wallet_verify_mnemonic(const unsigned char *mnemonic, int len, const unsigned char *passwd) {
	int ret = sapi_verify_mnemonic(passwd, PASSWD_HASHED_LEN, (const unsigned char *) mnemonic, len);
	if (ret != 0) {
		db_serr("verify mnemonic ret:%d", ret);
		return ret;
	}
	sec_state_info info;
	if (sapi_get_state_info(&info) != 0) {
		db_serr("get state info false");
		return -11;
	}
	if (info.seed_state != 1) {
		db_serr("invalid seed_state:%d", info.seed_state);
		return -12;
	}
	if (info.mnemonic == 0) {
		db_serr("state not have mnemonic");
		return -13;
	}
	return 0;
}

int wallet_store_passphrase(const unsigned char *passphrase, int len, const unsigned char *passwd) {
    int ret = sapi_set_passphrase(passwd, PASSWD_HASHED_LEN, (const unsigned char *) passphrase, len);
    if (ret != 0) {
        db_serr("set passphrase false ret:%d", ret);
        return ret;
    }
    gui_on_process(30);
    gSeedAccountId = 0;
    uint64_t id = wallet_getAccountId(1);
    if (!id) {
        db_serr("get account id false");
        return -41;
    }
    settings_set_have_seed(id);
    gui_on_process(60);
    wallet_initDefaultCoin(passwd);
    gui_on_process(90);
    return 0;
}

int wallet_destorySeed(int type, int precent) {
    db_secure("type:%d", type);
    wallet_cleanAccountInfo(type == 1 ? 1 : 0);
    if (precent > 0) {
        gui_on_process(precent);
    }
    settings_set_have_seed(0);
    if (precent > 0) {
        gui_on_process(precent + 10);
    }
    return sapi_destory_seed();
}

int wallet_getHDNode(int type, const char *uname, HDNode *hdnode) {
    PubHDNode node;
    int ret = wallet_getCoinPubHDNode(type, uname, NULL, &node);
    if (ret != 0) {
        db_error("get type:%d uname:%s false", type, uname);
        return ret;
    }
    if (PubHDNode2HDNode(&node, hdnode) != 0) {
        db_error("hdnode xchange false curv:%d type:%d uname:%s", node.curve, type, uname);
        return -42;
    }
    db_secure("curve:%p depth:%d child_num:0x%x chain_code:%s", hdnode->curve, hdnode->depth, hdnode->child_num,
              debug_ubin_to_hex(hdnode->chain_code, 32));
    db_secure("type:%d uname:%s public_key:%s", type, uname, debug_ubin_to_hex(hdnode->public_key, 33));
    return hdnode->public_key[0] == 0 ? -44 : 0;
}

int wallet_genAddress(char *address, int size, HDNode *hdnode, int type, const char *uname, uint32_t index, int testnet) {
	if (!address || size < 44 || index >= 0x80000000) {
		db_error("address:%p size:%d index:0x%x", address, size, index);
		if (address) *address = 0;
		return -1;
	}

    int ret;
    HDNode _hdnode;
    int local_node = 0;
    if (!hdnode) {
        memset(&_hdnode, 0, sizeof(HDNode));
        ret = wallet_getHDNode(type, uname, &_hdnode);
        if (ret != 0) {
            db_error("get hdnode false type:%d uname:%s", type, uname);
            if (address) *address = 0;
            return -1;
        }
        hdnode = &_hdnode;
        local_node = 1;
    }
    memset(address, 0, size);
    ret = coin_get_address(address, size, type, uname, hdnode, index, testnet);
    if (ret <= 0) {
        db_error("get address type:%d uname:%s index:%d test:%d false", type, uname, index, testnet);
    }
    if (local_node) {
        memset(&_hdnode, 0, sizeof(HDNode));
    }
    return ret;
}

int wallet_verify_seed_xpub(const unsigned char *seed, int seed_len) {
    int curv;
    const char *path = NULL;
    HDNode node;
    HDNode rootnode;
    PubHDNode pubnode;
    CoinPathInfo info;
    int ret = -1;
    uint64_t account_id = wallet_AccountId();
    if (!account_id) {
        db_error("not accout id");
        return -1;
    }
    memzero(&rootnode, sizeof(HDNode));
    if (hdnode_gen_from_seed(seed, seed_len, &secp256k1_info, &rootnode) != 0) {
        db_error("gen hdnode false");
        return -2;
    }

    cstring *data = cstr_new_sz(512);
    if (!data) {
        db_error("new cstring false");
        memzero(&rootnode, sizeof(HDNode));
        return -3;
    }
    int total = storage_get_xpub_exists_paths(account_id, data);
    db_msg("paths total:%d buff len:%d", total, data->len);
    if (total <= 0) {
        cstr_free(data);
        memzero(&rootnode, sizeof(HDNode));
        return -4;
    }
    const char *p = (const char *) data->str;
    int j;
    int i;
    for (i = 0; i < total; i++) {
        curv = *(p + 1);
        path = p + 2;
        p += (*p + 1);
        ret = -1;
        memset(&pubnode, 0, sizeof(PubHDNode));
        memset(&info, 0, sizeof(CoinPathInfo));
        db_msg("gen curv:%d path:%s", curv, path);
        if (curv != CURVE_SECP256K1) {
            ret = 0;
            continue;
        }
        if (parse_coin_path(&info, path) != 0) {
            db_error("invalid path:%s", path);
            ret = -11;
            break;
        }
        ret = wallet_getPubHDNode(curv, path, NULL, &pubnode);
        if (ret) {
            db_error("get pubnode curv:%d path:%s ret:%d", curv, path, ret);
            break;
        }
        memcpy(&node, &rootnode, sizeof(HDNode));
        for (j = 0; j < info.hn; j++) {
            hdnode_private_ckd_prime(&node, info.hvalues[j]);
        }
        hdnode_fill_public_key(&node);
        if (pubnode.depth != node.depth || pubnode.child_num != node.child_num) {
            db_error("invalid pubnode depth:%d child_num:%d != node depth:%d child_num:%d", pubnode.depth,
                     pubnode.child_num, node.depth, node.child_num);
            ret = -101;
            break;
        }
        if (memcmp(pubnode.public_key, node.public_key, 33) != 0) {
            db_error("invalid public_key pub:%s", debug_ubin_to_hex(pubnode.public_key, 33));
            db_error("invalid public_key node:%s", debug_ubin_to_hex(node.public_key, 33));
            ret = -102;
            break;
        }
        if (memcmp(pubnode.chain_code, node.chain_code, 32) != 0) {
            db_error("invalid chain_code pub:%s", debug_ubin_to_hex(pubnode.chain_code, 32));
            db_error("invalid chain_code node:%s", debug_ubin_to_hex(node.chain_code, 32));
            ret = -103;
            break;
        }
        ret = 0;
    }
    while (0);
    cstr_free(data);
    memzero(&node, sizeof(HDNode));
    memzero(&pubnode, sizeof(PubHDNode));
    memzero(&rootnode, sizeof(HDNode));
    db_msg("check seed end total:%d try:%d ret:%d", total, i, ret);
    return ret;
}

int wallet_verify_xpub(const unsigned char *passwd, int type, const char *uname) {
    PubHDNode node;
    PubHDNode node2;
    int ret = wallet_getCoinPubHDNode(type, uname, NULL, &node);
    if (ret != 0) {
        db_error("get type:%d uname:%s false", type, uname);
        return ret;
    }

    uint16_t curv = coin_get_curv_id(type, uname);
    const char *path = coin_get_hdnode_path(type, uname);
    ret = wallet_queryPubHDNode(curv, path, passwd, &node2);
    if (ret != 0) {
        db_error("query PubHDNode type:%d uname:%s curv:%d path:%s", type, uname, curv, path);
        return ret;
    }
    if (memcmp(&node, &node2, sizeof(PubHDNode)) != 0) {
        db_error("node diff");
        return -101;
    }
    db_msg("check xpub type:%d uname:%s OK", type, uname);
    return 0;
}
