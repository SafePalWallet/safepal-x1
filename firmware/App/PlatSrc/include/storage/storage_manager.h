#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include "coin_util.h"
#include "cstr.h"

#define SM_ERROR_TOO_MUCH_CLIENT (-201)
#define CLIENT_SECKEY_SIZE    32
#define CLIENT_NAME_MAX_LEN   31
#define CLIENT_UNIQID_MAX_LEN  20

typedef struct {
    int client_id;
    unsigned int bind_time;
    unsigned char seckey[CLIENT_SECKEY_SIZE];
    char unique_id[CLIENT_UNIQID_MAX_LEN + 1];
    char client_name[CLIENT_NAME_MAX_LEN + 1];
} ClientInfo;

typedef struct {
    uint8_t type;
    uint8_t curv;
    uint8_t decimals;
    uint8_t _resv; //padding
    char uname[COIN_UNAME_BUFFSIZE];
    char name[COIN_NAME_BUFFSIZE];
    char symbol[COIN_SYMBOL_BUFFSIZE];
    int32_t flag;
} DBCoinInfo;

typedef struct {
    int id;
    int msg_type;
    int time;
    int time_zone;
    int client_id;
    int flag;
    int tx_type;
    int coin_type;
    char coin_uname[COIN_UNAME_BUFFSIZE];
    char coin_name[COIN_NAME_BUFFSIZE];
    char coin_symbol[COIN_SYMBOL_BUFFSIZE];
    char send_value[40];
    char currency_value[40];
    char currency_symbol[8];
    cstring *data;
} DBTxInfo;

int storage_cleanAllData(void);

int storage_upgrade(uint64_t account_id);

int storage_queryClientId(const char *unique_id);

int storage_queryClientUniqueId(int client_id, char *unique_id);

int storage_getClientInfo(int client_id, ClientInfo *client);

int storage_getClientSeckey(int client_id, unsigned char *key);

int storage_saveClientInfo(ClientInfo *client);

int storage_getXpubInfo(uint64_t account_id, uint16_t curv, const char *path, uint8_t *xpub_bin, int xpub_size);

int storage_get_xpub_exists_paths(uint64_t account_id, cstring *data);

int storage_saveXpubInfo(uint64_t account_id, uint16_t curv, const char *path, uint8_t *xpub_bin, int xpub_size);

int storage_save_coin(int type, const char *uname);

int storage_save_coin_info(const CoinConfig *config);

int storage_save_coin_dbinfo(const DBCoinInfo *info);

int storage_set_coin_flag(uint8_t type, const char *uname, int value);

int storage_deleteCoinInfo(int type, const char *uname);

int storage_isCoinExist(int type, const char *uname);

int storage_queryCoinInfo(DBCoinInfo *info, int size, int offset, int not_hide);

int storage_getCoinsCount(int not_hide);

int storage_set_account_name(uint64_t account_id, char *name, int len);

int storage_get_account_name(uint64_t account_id, char *name, int len);

int storage_get_coin_max_index(uint64_t account_id, int coin_id);

int storage_set_coin_max_index(uint64_t account_id, int coin_id, int new_index);

int storage_checkExistClientId(void);

#endif 

