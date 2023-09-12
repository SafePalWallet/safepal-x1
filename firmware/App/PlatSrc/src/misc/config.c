#define LOG_TAG "config.c"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "debug.h"
#include "libddi.h"

/*
#ifdef ALOGD
#undef ALOGD
#undef ALOGW
#endif
#define ALOGD(fmt, ...) printf("<%s:%04d>"fmt"\n",__func__, __LINE__, ##__VA_ARGS__)
#define ALOGW(fmt, ...) printf("<%s:%04d>"fmt"\n",__func__, __LINE__, ##__VA_ARGS__)
*/

typedef struct {
	const char *key;
	char *value;
	int size;
	int ret_size;
} find_key_session_st;

typedef struct {
	const char *key;
	const char *new_value;
	char *buff;
	int total;
	int size;
	int same;
	int save_new;
} set_key_session_st;

static int set_find_key_cb(void *user, const char *key, const char *val) {
	set_key_session_st *tg = (set_key_session_st *) user;
	if (!tg->save_new && tg->key[0] == *key && strcmp(tg->key, key) == 0) {
		if (strcmp(val, tg->new_value) == 0) {
			tg->same = 1;
		} else {
			tg->same = 0;
		}
		return 0;
	}
	int left = tg->total - tg->size;
	if (left < 5) {
		ALOGE("config file overload");
		return 1;
	}
	int len = snprintf(tg->buff + tg->size, left, "%s=%s\n", key, val);
	if (len > left) { //overload
		tg->buff[tg->size] = 0;
		ALOGE("config file overload");
		return 1;
	} else {
		tg->size += len;
		return 0;
	}
}

int config_file_set(const char *file, const char *key, const char *value) {
	int ret;
	char tmpbuf[1024];
	set_key_session_st tg[1];
	if (!key || *key == 0) {
		return -1;
	}
	db_msg("config_file_set file:%s %s = %s", file, key, value);
	int isdel = (!value || *value == 0) ? 1 : 0;
	tg->key = key;
	tg->new_value = value;
	tg->same = 0;
	tg->buff = tmpbuf;
	tg->total = sizeof(tmpbuf);
	tg->size = 0;
	tg->save_new = 0;

	int exist = ddi_vfs_access(file) == 0;
	if (exist) {
		ret = config_file_read(file, set_find_key_cb, tg);
		if (ret != 0) {
			ALOGE("read file:%s false", file);
			return -1;
		}
	}
	if (tg->same) {
		db_msg("config_file_set update item:%s to %s,same as old,skip", key, value);
		return 0;
	}
	if (!isdel) {
		tg->save_new = 1;
		ret = set_find_key_cb(tg, key, value);//tmpbuf:"%s=%s\n"
		if (ret != 0) {
			ALOGE("set file:%s key:%s value:%s fail ret:%d", file, key, value, ret);
			return -1;
		}
	}
	if (tg->size == 0) {
		if (exist) {
			ALOGE("not config,delete file:%s", file);
			ddi_vfs_remove(file);
		}
		return 0;
	}
	int fp = ddi_vfs_open(file, "wb");
	if (fp <= 0) {
		ALOGW("config_file_set open file:%s error", file);
		return -1;
	}
	ddi_vfs_write(tmpbuf, tg->size, fp);
	ddi_vfs_close(fp);
	return 0;
}

int config_file_set_int(const char *file, const char *key, int value) {
	char intbuf[20];
	snprintf(intbuf, sizeof(intbuf), "%d", value);
	return config_file_set(file, key, intbuf);
}

static int find_key_cb(void *user, const char *key, const char *val) {
	find_key_session_st *tg = (find_key_session_st *) user;
	if (tg->key[0] == *key && strcmp(tg->key, key) == 0) {
		tg->ret_size = strlcpy(tg->value, val, tg->size);
		return tg->ret_size;
	}
	return 0;
}

int config_file_get(const char *file, const char *key, char *value, int size) {
	find_key_session_st tg[1];
	tg->key = key;
	tg->value = value;
	tg->size = size;
	tg->ret_size = 0;
	int ret = config_file_read(file, find_key_cb, tg);
	if (ret != 0) {
		return -1;
	}
	return tg->ret_size;
}

int config_file_get_int(const char *file, const char *key, int default_val) {

	char intbuf[32] = {0};
	int ret = config_file_get(file, key, intbuf, sizeof(intbuf));
	return (ret > 0) ? atoi(intbuf) : default_val;
}

int config_file_read(const char *file, int (*callback)(void *user, const char *key, const char *val), void *user) {
	db_msg("start config_file_read file:%s", file);
	char tmpbuf[256];
	char *item_key, *item_value, *tmp;
	int len;
    char *end, *head;
    char oneLine[64];
    int itemLen = 0, sumLen=0, offset=0, find=0;
	
	int fp = ddi_vfs_open(file, "r");
	if (fp <= 0) {
		ALOGW("config_file_read open file:%s error", file);
		return -1;
	}

	while (1) {
		memset(tmpbuf, 0x0, sizeof(tmpbuf));
		ddi_vfs_seek(fp, offset, SEEK_SET);
		len = ddi_vfs_read(tmpbuf, sizeof(tmpbuf), fp);
		if((len <= 0) || (find==1)){
			db_msg("file to end");
			break;
		}
		
		while(1){
			memset(oneLine, 0x0, sizeof(oneLine));
			end = strchr(tmpbuf+sumLen, '\n');
			if (end == 0) {
				offset+=sumLen;
				db_msg("tmpbuf to end");
				break;
			}
			head = tmpbuf+sumLen;
			itemLen = end-head+1;
			strncpy(oneLine, head, itemLen);
			db_msg("oneLine:%s",oneLine);
			sumLen += itemLen;
			
			item_key = oneLine;
			item_value = strchr(oneLine, '=');
			if (item_value == 0) {
				continue;
			}
			*item_value++ = 0;
			
			while (isspace(*item_key)) item_key++;
			if (*item_key == '#') continue;
			tmp = item_value - 2;
			while ((tmp > item_key) && isspace(*tmp)) *tmp-- = 0;
			
			while (isspace(*item_value)) item_value++;
			tmp = item_value + strlen(item_value) - 1;
			while ((tmp >= item_value) && (isspace(*tmp) || *tmp == '\n' || *tmp == '\r')) *tmp-- = 0;
			
			if (strlen(item_key) > 0 && strlen(item_value) > 0) {
				if (callback(user, item_key, item_value) != 0) {
					find = 1;
					break;
				}
			}
		}
	}
	ddi_vfs_close(fp);
	db_msg("end config_file_read file:%s", file);
	return 0;
}
