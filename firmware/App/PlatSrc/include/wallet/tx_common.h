#ifndef WALLET_TX_COMMON_H
#define WALLET_TX_COMMON_H

#include "wallet_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Length of the ext_header (and optional time header) prefixed to msg->data.
// Returns the byte length (>=0), or <0 on a malformed header.
int GetExtHeaderLen(const ProtoClientMessage *msg);

// Compute the 6-digit verification code shared between device and companion app.
// code = SHA256(SHA256(sn + client_unique_id + client_id + account_id + tx_data)) % 1000000
// Returns the code (>0), or <0 on error.
int TxGetVerifyCode(const ProtoClientMessage *msg);

#ifdef __cplusplus
}
#endif
#endif
