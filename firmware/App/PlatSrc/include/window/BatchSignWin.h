#ifndef WALLET_BATCH_SIGN_WIN_H
#define WALLET_BATCH_SIGN_WIN_H

#ifdef __cplusplus
extern "C" {
#endif

// Batch sign window. Receives a batch sign request (via global mMessage),
// shows the shared verification code + a selectable list of transactions,
// signs all with a single PIN, and returns all results in one QR.
// Returns: 0 = all signed & QR sent; KEY_EVENT_ABORT = user cancelled;
//          RETURN_DISP_MAINPANEL = error/aborted batch.
int BatchSignWin(void);

#ifdef __cplusplus
}
#endif
#endif
