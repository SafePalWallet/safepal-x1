#ifndef WALLET_WALLETMANAGER_H
#define WALLET_WALLETMANAGER_H

#include "wallet_proto.h"
#include "wallet_util.h"
#include "secure_api.h"

#define PRIVATE_PASSWD_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

int wallet_init0(void);

int wallet_init(void);

int wallet_isInited(void);

const sec_base_info *wallet_getBaseInfo(void);

int wallet_getPasswdAllowErrorTimes(void);

uint64_t wallet_getAccountId(int refresh);

uint64_t wallet_AccountId(void);

int wallet_getAccountSuffix(char suffix[4]);

int wallet_queryPubHDNode(uint16_t curv, const char *path, const unsigned char *passwd, PubHDNode *node);

int wallet_getPubHDNode(uint16_t curv, const char *path, const unsigned char *passwd, PubHDNode *node);

int wallet_getCoinPubHDNode(int type, const char *uname, const unsigned char *passwd, PubHDNode *node);

int wallet_check_hdnode_exist(uint16_t curv, const char *path);

int wallet_genPathPubHDNode(const unsigned char *passwd, int curv, const char *path);

int wallet_genDefaultPubHDNode(const unsigned char *passwd, int type, const char *uname);

int wallet_gen_exists_hdnode(const unsigned char *passwd, uint64_t old_account_id);

int wallet_initDefaultCoin(const unsigned char *passwd);

int wallet_storeSeed(unsigned char *seed, int seedlen, const unsigned char *passwd);

int wallet_storeCardanoPrivate(unsigned char *seed, int seedlen, const unsigned char *passwd);

int wallet_verify_mnemonic(const unsigned char *mnemonic, int len, const unsigned char *passwd);

int wallet_store_passphrase(const unsigned char *passphrase, int len, const unsigned char *passwd);

int wallet_destorySeed(int type, int precent);

int wallet_getHDNode(int type, const char *uname, HDNode *hdnode);

int wallet_genAddress(char *address, int size, HDNode *hdnode, int type, const char *uname, uint32_t index, int testnet);

int wallet_verify_seed_xpub(const unsigned char *seed, int seed_len);

int wallet_verify_xpub(const unsigned char *passwd, int type, const char *uname);

#ifdef __cplusplus
}
#endif
#endif

