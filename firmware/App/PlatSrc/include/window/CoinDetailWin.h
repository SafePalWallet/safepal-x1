#ifndef WALLET_COINDETAILWIN_H
#define WALLET_COINDETAILWIN_H

#include "coin_util.h"

typedef struct {
    int type;
    char uname[COIN_UNAME_BUFFSIZE];
    char symbol[COIN_SYMBOL_BUFFSIZE];
    char chain_name[COIN_NAME_BUFFSIZE];
} type_uname;

int CoinDetailWin(int param);

#endif
