#ifndef BT_RECV_WIN_H_
#define BT_RECV_WIN_H_

void BtRecvInit(void);

void BtRecvDeinit(void);

void BtRecvProcCode(void);

int onBtResult(const char *data, int size);

int onBtRecvData(uint8_t *recvBuff, uint32_t bufLen);

#endif /**/
