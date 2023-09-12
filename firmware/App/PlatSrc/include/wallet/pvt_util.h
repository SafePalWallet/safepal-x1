#ifndef WALLET_PVT_UTIL_H
#define WALLET_PVT_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

int pvtDecodeActiveInfo(PvtActiveInfo *info, const unsigned char *data, int len);

int pvtGenProductInfoData(unsigned char *product_info, int len);

int pvtAfterActive();

#ifdef __cplusplus
}
#endif

#endif
