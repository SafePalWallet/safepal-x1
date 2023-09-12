#ifndef TRUNK_RECEIVEADDRLIST_H
#define TRUNK_RECEIVEADDRLIST_H

#include <stdint.h>

typedef int (*gen_index_address_func)(void *user, char *address, int size, uint32_t index);

int showAddrList(HWND parent, int maxIndex, int newIndex, char *inoutAddress, int *inoutIndex,
                 gen_index_address_func gen_func, void *user);

#endif
