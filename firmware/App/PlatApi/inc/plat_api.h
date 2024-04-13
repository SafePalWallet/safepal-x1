#ifndef __PLAT_API_H__
#define __PLAT_API_H__

#include <stdbool.h>
#include <stdint.h>

#define ddi_id(x) ddi_id_##x

typedef struct {
    int cmd;
    void *p;
} ddi_cmd_item;

typedef struct {
    int (*sys_msleep)(uint32_t nMs);

    int (*sys_set_time)(const uint8_t *lpTime);

    int (*sys_get_time)(uint8_t *lpTime);

    int (*sys_get_tick)(uint32_t *time_ms);

    int (*sys_get_firmware_ver)(uint8_t nType);

    int (*sys_bat_status)(void);

    int (*sys_bat_vol)(void);

    int (*sys_poweroff)(void);

    int (*sys_reboot)(void);

    int (*sys_get_machtype)(void);

    int (*sys_cmd)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);
} ddi_sys_list_t;

typedef struct {
    void *(*mem_malloc)(uint32_t size);

    void (*mem_free)(void *ptr);

    void *(*mem_realloc)(void *ptr, uint32_t size);
} ddi_mem_list_t;

typedef struct {
    int (*vfs_mount)(const char *path);

    int (*vfs_unmount)(const char *path);

    int (*vfs_mkfs)(const char *path);

    int (*vfs_open)(const char *lpPath, const char *lpMode);

    int (*vfs_close)(int nHandle);

    int (*vfs_write)(const uint8_t *lpData, int nLen, int nHandle);

    int (*vfs_read)(uint8_t *lpData, int nLen, int nHandle);

    int (*vfs_seek)(int nHandle, int nOffset, int nWhence);

    int (*vfs_tell)(int nHandle);

    int (*vfs_remove)(const char *lpFileName);

    int (*vfs_rename)(const char *lpOldName, const char *lpNewName);

    int (*vfs_filesize)(const char *lpName);

    int (*vfs_ioctl)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);
} ddi_vfs_list_t;

typedef struct {
    int (*bt_open)(void);

    int (*bt_close)(void);

    int (*bt_disconnect)(void);

    int (*bt_write)(uint8_t *lpIn, uint32_t nLe);

    int (*bt_read)(uint8_t *lpOut, uint32_t nLe);

    int (*bt_get_status)(void);

    int (*bt_ioctl)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);
} ddi_bt_list_t;

typedef struct {
    int (*flash_write)(uint32_t addr, const uint8_t *data, uint32_t size);

    int (*flash_read)(uint32_t addr, uint8_t *data, uint32_t size);

    int (*flash_sector_erase)(uint32_t addr);

    int (*flash_ioctl)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);
} ddi_flash_list_t;

typedef struct {
    int (*lcd_open)(void);

    int (*lcd_close)(void);

    int (*lcd_clear_rect)(const strRect *lpstrRect);

    int (*lcd_show_text)(uint32_t nX, uint32_t nY, const char *lpText);

    int (*lcd_show_picture)(const strRect *lpstrRect, const strPicture *lpstrPic);

    int (*lcd_show_pixel_ex)(uint32_t nX, uint32_t nY);

    int (*lcd_show_line)(const strLine *lpstrLine);

    int (*lcd_show_rect)(const strRect *lpstrRect);

    void (*lcd_brush)(const strRect *lpstrRect);

    void (*lcd_brush_screen)(void);

    int (*lcd_ioctl)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

    int (*lcd_clear_screen)();

    int (*lcd_fill_row_ram)(uint32_t nRow, uint32_t nCol, const char *lpText, uint32_t flag);

    int (*lcd_clear_row)(uint32_t nRow);

    int (*lcd_get_text_width)(const char *lpText, int size);
} ddi_lcd_list_t;

typedef struct {
    int (*key_open)(void);

    int (*key_clear)(void);

    int (*key_read)(uint32_t *key);

    int (*key_ioctl)(uint32_t cmd, uint32_t lparam, uint32_t wparam);

    int (*key_close)(void);
} ddi_key_list_t;

typedef struct {
    int (*usb_open)(void);

    int (*usb_close)(void);

    int (*usb_read)(uint8_t *lpOut, uint32_t nLe);

    int (*usb_write)(uint8_t *lpIn, uint32_t nLe);

    int (*usb_ioctl)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

} ddi_usb_list_t;

typedef struct {
    int (*uart_open)(uint32_t nCom, uint32_t baudrate);

    int (*uart_close)(uint32_t nCom);

    int (*uart_read)(uint32_t nCom, uint8_t *lpOut, uint32_t nLe);

    int (*uart_write)(uint32_t nCom, uint8_t *lpIn, uint32_t nLe);

    int (*uart_ioctl)(uint32_t nCom, uint32_t nCmd, uint32_t lParam, uint32_t wParam);
} ddi_uart_list_t;

typedef struct {
    int (*tamper_cfg)(void);

    int (*tamper_get_stat)(void);

    int (*tamper_clr)(void);

    int (*calc_sha1)(uint8_t *pData, uint32_t dataLen, uint8_t *pHashValue);

    int (*calc_sha256)(uint8_t *pData, uint32_t dataLen, uint8_t *pHashValue);

    int (*calc_md5)(uint8_t *pData, uint32_t dataLen, uint8_t *pMd5Value);

    int (*get_randnum)(uint8_t *pData, uint32_t dataLen);

    int (*get_cpuid)(uint8_t *buff, int size);

    int (*sec_rsa_pk_dec)(uint8_t *ppkey, uint8_t *pdata, uint32_t datalen, uint8_t *poutdata, uint32_t *poutlen);

    int (*sec_rsa_sk_enc)(uint8_t *pskey, uint8_t *pdata, uint32_t datalen, uint8_t *poutdata, uint32_t *poutlen);

    int (*sec_reset_randkey)(int op);

    int (*sec_read_randkey)(unsigned char result[32]);

    int (*sec_sapi_command)(unsigned char cmd, unsigned char inlen, const unsigned char *inbuf, unsigned char *outbuf);

    int (*sec_read_vsn)(unsigned char result[32]);

    int (*sec_read_chipid)(unsigned char result[32]);

    int (*sec_ecdsa_verify_digest)(int curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);

    int (*sec_ecdsa_digital_sign)(int curve, const uint8_t *pri_key, uint8_t *sig, const uint8_t *digest);

    int (*sec_smgt_ioctl)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

} ddi_sec_list_t;

typedef struct {
    int (*ota_prepare)(void);

    int (*ota_upgrade)(void);

    int (*ota_ioctl)(uint32_t nCmd, uint32_t lParam, uint32_t wParam);
} ddi_ota_list_t;

typedef struct {
    void (*soft_timer_start)(uint16_t id, tmrMode mode, uint32_t delay, callback *cb, void *argv, uint16_t argc);

    uint8_t (*soft_timer_get_state)(uint16_t id);

    int (*soft_timer_is_timeout)(uint16_t id);

    void (*soft_timer_stop)(uint16_t id);
} ddi_soft_timer_list_t;

enum {
    ddi_id(sys_msleep) = 0x101,
    ddi_id(sys_set_time),
    ddi_id(sys_get_time),
    ddi_id(sys_get_tick),
    ddi_id(sys_get_firmware_ver),
    ddi_id(sys_bat_status),
    ddi_id(sys_bat_vol),
    ddi_id(sys_poweroff),
    ddi_id(sys_reboot),
    ddi_id(sys_get_machtype),
    ddi_id(sys_cmd),
    ddi_id(mem_malloc) = 0x201,
    ddi_id(mem_free),
    ddi_id(mem_realloc),
    ddi_id(vfs_mount) = 0x301,
    ddi_id(vfs_unmount),
    ddi_id(vfs_mkfs),
    ddi_id(vfs_open),
    ddi_id(vfs_close),
    ddi_id(vfs_write),
    ddi_id(vfs_read),
    ddi_id(vfs_seek),
    ddi_id(vfs_tell),
    ddi_id(vfs_remove),
    ddi_id(vfs_rename),
    ddi_id(vfs_filesize),
    ddi_id(vfs_ioctl),
    ddi_id(bt_open) = 0x401,
    ddi_id(bt_close),
    ddi_id(bt_disconnect),
    ddi_id(bt_write),
    ddi_id(bt_read),
    ddi_id(bt_get_status),
    ddi_id(bt_ioctl),
    ddi_id(flash_write) = 0x501,
    ddi_id(flash_read),
    ddi_id(flash_sector_erase),
    ddi_id(flash_ioctl),
    ddi_id(lcd_open) = 0x601,
    ddi_id(lcd_close),
    ddi_id(lcd_clear_rect),
    ddi_id(lcd_show_text),
    ddi_id(lcd_show_picture),
    ddi_id(lcd_show_pixel_ex),
    ddi_id(lcd_show_line),
    ddi_id(lcd_show_rect),
    ddi_id(lcd_brush),
    ddi_id(lcd_brush_screen),
    ddi_id(lcd_ioctl),
    ddi_id(lcd_clear_screen),
    ddi_id(lcd_fill_row_ram),
    ddi_id(lcd_clear_row),
    ddi_id(lcd_get_text_width),
    ddi_id(key_open) = 0x701,
    ddi_id(key_clear),
    ddi_id(key_read),
    ddi_id(key_ioctl),
    ddi_id(key_close),
    ddi_id(usb_open) = 0x801,
    ddi_id(usb_close),
    ddi_id(usb_read),
    ddi_id(usb_write),
    ddi_id(usb_ioctl),
    ddi_id(uart_open) = 0x901,
    ddi_id(uart_close),
    ddi_id(uart_read),
    ddi_id(uart_write),
    ddi_id(uart_ioctl),
    ddi_id(tamper_cfg) = 0xA01,
    ddi_id(tamper_get_stat),
    ddi_id(tamper_clr),
    ddi_id(calc_sha1) = 0xB01,
    ddi_id(calc_sha256),
    ddi_id(calc_md5),
    ddi_id(get_randnum),
    ddi_id(get_cpuid),
    ddi_id(sec_rsa_pk_dec),
    ddi_id(sec_rsa_sk_enc),
    ddi_id(sec_reset_randkey),
    ddi_id(sec_read_randkey),
    ddi_id(sec_sapi_command),
    ddi_id(sec_read_vsn),
    ddi_id(sec_read_chipid),
    ddi_id(sec_ecdsa_verify_digest),
    ddi_id(sec_ecdsa_digital_sign),
    ddi_id(sec_smgt_ioctl),
    ddi_id(ota_prepare) = 0xC01,
    ddi_id(ota_upgrade),
    ddi_id(ota_ioctl),
    ddi_id(soft_timer_start) = 0xD01,
    ddi_id(soft_timer_get_state),
    ddi_id(soft_timer_is_timeout),
    ddi_id(soft_timer_stop),
};

#endif

