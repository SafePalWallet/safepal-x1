#include "coin_util.h"
#include "coin_util_hw.h"
#include "common_util.h"
#include "bignum.h"
#include "debug.h"

int is_coin_address_long(int coinid) {
	return (coinid == COIN_TYPE_EOS || coinid == COIN_TYPE_XLM || coinid == COIN_TYPE_NEAR) ? 1 : 0;
}

int format_data_to_hex(const unsigned char *bytes, int size, char *tmpbuf, int bufflen) {
	int ret;
	memset(tmpbuf, 0, bufflen);
	if (size * 2 < (bufflen - 2)) {
		tmpbuf[0] = '0';
		tmpbuf[1] = 'x';
		bin_to_hex(bytes, size, tmpbuf + 2);
	} else {
		tmpbuf[0] = '0';
		tmpbuf[1] = 'x';
		ret = (bufflen / 4) - 3;
		bin_to_hex(bytes, ret, tmpbuf + 2);
		ret *= 2;
		ret += 2;
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		bin_to_hex(bytes + size - ((bufflen / 4) - 3), (bufflen / 4) - 3, tmpbuf + ret);
	}
	return strlen(tmpbuf);
}

int format_data_to_hex_b(const unsigned char *bytes, int size, char *tmpbuf, int bufflen) {
	int ret;
	memset(tmpbuf, 0, bufflen);
	if (size * 2 < bufflen) {
		bin_to_hex_b(bytes, size, tmpbuf);
	} else {
		ret = (bufflen / 4) - 3;
		bin_to_hex_b(bytes, ret, tmpbuf);
		ret *= 2;
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		tmpbuf[ret++] = '.';
		bin_to_hex_b(bytes + size - ((bufflen / 4) - 3), (bufflen / 4) - 3, tmpbuf + ret);
	}
	return strlen(tmpbuf);
}

int bignum2double(const unsigned char *bytes, int size, uint8_t decimals, double *value, char *value_str, size_t value_str_size) {
	uint8_t buff[32];
	char float_str[44] = {0};
	if (size < 1) {
		if (value) *value = 0;
		db_error("invalid size:%d", size);
		return -1;
	}
	if (size > 32) {
		if (value) *value = 0;
		db_error("invalid size:%d", size);
		return -410;
	}
	if (decimals > 40) {
		db_error("invalid decimals:%d", decimals);
		return -1;
	}
	int i = 32 - size;
	memset(buff, 0, 32);
	memcpy(buff + i, bytes, size);
	db_msg("buff:%s decimals:%d", debug_ubin_to_hex(buff, 32), decimals);
	bignum256 bn;
	bn_read_be(buff, &bn);
	uint32_t r0 = 0;
	double f = 0;
	uint8_t dec2 = decimals;
	uint8_t dlen = 0;
	char *floatp = float_str + decimals - 1;
	while (dec2 > 0) {
		bn_divmod10(&bn, &r0);
		dec2 -= 1;
		if (dlen || r0) dlen++;
		f = (f / 10) + ((double) r0) / 10;
		*floatp = '0' + r0;
		//db_msg("dv10 dec2:%d r0:%u f:%.10lf dlen:%d float:%s", dec2, r0, f, dlen, floatp);
		floatp -= 1;
	}
	if (decimals && !dlen) dlen = 1; // limit mini 1 float char
	float_str[dlen] = 0;

	uint64_t u64 = bn_write_uint64(&bn);
	if (value) {
		bignum256 bn53;
		bn_read_uint64(0x20000000000000ULL, &bn53);
		if (!bn_is_less(&bn, &bn53)) { //limit max 2^53
			db_error("too big unmber");
			return -411;
		}
		*value = (double) u64 + f;
	}

	if (value_str) {
		if (dlen) {
			snprintf(value_str, value_str_size, "%llu.%s", u64, float_str);
		} else {
			snprintf(value_str, value_str_size, "%llu", u64);
		}
		db_msg("value_str:%s", value_str);
	}
	db_msg("decimals:%d u64:%llu value:%.8lf float_str:%s", decimals, u64, f, float_str);
	if (value) {
		db_msg("f:%.18lf value:%.18lf", f, *value);
	}
	return 0;
}

int bignum_print(const unsigned char *bytes, int size, uint8_t decimals, const char *prefix, char *value_str, size_t value_str_size) {
	if (size < 1) {
		*value_str = 0;
		return 0;
	}
	if (size > 32) {
		*value_str = 0;
		return 0;
	}
	uint8_t buff[32];
	int i = 32 - size;
	memset(buff, 0, 32);
	memcpy(buff + i, bytes, size);
	bignum256 bn;
	bn_read_be(buff, &bn);
	return bn_format(&bn, prefix, NULL, decimals, 0, 0, value_str, value_str_size);
}
