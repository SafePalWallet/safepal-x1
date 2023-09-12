
#ifndef TRUNK_CONFIRMSEEDWORD_H
#define TRUNK_CONFIRMSEEDWORD_H

#include <stdlib.h>

typedef struct {
    const uint16_t *seeds;
    uint8_t seedWordCnt;
} ConfirmSeedWordConfig_t;

extern int showConfirmSeedWord(ConfirmSeedWordConfig_t *config);

#endif
