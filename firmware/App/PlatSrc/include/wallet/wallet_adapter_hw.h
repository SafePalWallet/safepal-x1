#ifndef WALLET_ADAPTER_HW_H
#define WALLET_ADAPTER_HW_H

#include "wallet_manager.h"
#include "resource.h"

#ifndef VIEW_CODE_IN_IDE
#define wallet_get_pub_hdnode wallet_getPubHDNode
#define wallet_get_hdnode wallet_getHDNode
#define wallet_gen_address wallet_genAddress
#define wallet_sign_digest sapi_sign_digest
#endif
#endif
