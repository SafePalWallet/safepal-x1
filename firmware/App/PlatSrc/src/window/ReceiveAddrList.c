#define LOG_TAG "ReceiveAddrList"

#include "debug.h"
#include "ex_types.h"
#include "ReceiveAddrList.h"

#define LIST_ITEM_COUNT 3
#define LIST_ITEM_SELECT_INDEX 1

#define IDC_TITLE 650

#define IDC_CONTAINER(i) (1000+(i))
#define IDC_ITEM_TITLE(i) (2000+(i))
#define IDC_ADDR(i) (3000+(i))
#define IDC_BG(i) (4000+(i))

#define ADDRESS_BUFFER_SIZE 130
typedef struct {
    uint32_t index;
    char address[ADDRESS_BUFFER_SIZE];
} ReceiveIndexAddrData;

typedef struct {
    gen_index_address_func gen_func;
    void *user;
    int maxIndex;
    int *outIndex;
    char *outAddress;
    ReceiveIndexAddrData address[LIST_ITEM_COUNT];
    HWND containerHwnds[LIST_ITEM_COUNT];
    HWND addrHwnds[LIST_ITEM_COUNT];
    HWND itemTitleHwnds[LIST_ITEM_COUNT];
    HWND bgHwnds[LIST_ITEM_COUNT];
    HWND titleHwnd;
    int curIndex;
    int newIndex;
} ReceiveAddrListState_t;
