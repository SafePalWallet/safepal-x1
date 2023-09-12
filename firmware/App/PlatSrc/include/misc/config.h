#ifndef WALLET_CONFIG_H
#define WALLET_CONFIG_H
#ifdef __cplusplus
extern "C" {
#endif

int config_file_set(const char *file, const char *key, const char *value);

int config_file_set_int(const char *file, const char *key, int value);

int config_file_get(const char *file, const char *key, char *value, int size);

int config_file_get_int(const char *file, const char *key, int default_val);

int config_file_read(const char *file, int (*callback)(void *user, const char *key, const char *val), void *user);


#ifdef __cplusplus
}
#endif
#endif
