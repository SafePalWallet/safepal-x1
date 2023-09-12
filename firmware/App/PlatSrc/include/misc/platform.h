#ifndef _PLATFORM_H
#define _PLATFORM_H

//#define DEV_DEBUG_IGNORE_SEED
#ifdef DEBUG_TEMP_QUICKLY
#define DATA_POINT "/system/res"
#else
#define DATA_POINT "0:"
#endif
#define DATA_PATH DATA_POINT

#ifdef VIEW_CODE_IN_IDE

#include "plat_config_ide.h"

#endif

#ifdef BUILD_FOR_MCU
#endif

#ifndef WALLET_PLAT_CONFIG_H
//#error "not define platform"
#endif

#endif
