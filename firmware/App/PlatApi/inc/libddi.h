#ifndef __LIBDDI_H__
#define __LIBDDI_H__

#include "plat_api.h"

void init_ddi_item(const ddi_cmd_item *items);

int ddi_sys_msleep(uint32_t nMs);

int ddi_sys_set_time(const uint8_t *lpTime);

int ddi_sys_get_time(uint8_t *lpTime);

int ddi_sys_get_tick(uint32_t *nTick);

int ddi_sys_get_firmware_ver(uint8_t nType);

int ddi_sys_bat_status(void);

int ddi_sys_bat_vol(void);

int ddi_sys_poweroff(void);

int ddi_sys_reboot(void);

int ddi_sys_get_machtype(void);

int ddi_sys_cmd(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

uint32_t get_diff_tick(uint32_t cur_tick, uint32_t prior_tick);

int ddi_utils_stimer_query(uint32_t stimer, uint32_t timout_ms);

void *ddi_mem_malloc(uint32_t size);

void ddi_mem_free(void *ptr);

void *ddi_mem_realloc(void *ptr, uint32_t size);

int ddi_vfs_mount(const char *path);

int ddi_vfs_unmount(const char *path);

int ddi_vfs_mkfs(const char *path);

int ddi_vfs_open(const char *lpPath, const char *lpMode);

int ddi_vfs_close(int nHandle);

int ddi_vfs_write(const uint8_t *lpData, int nLen, int nHandle);

int ddi_vfs_read(uint8_t *lpData, int nLen, int nHandle);

int ddi_vfs_seek(int nHandle, int nOffset, int nWhence);

int ddi_vfs_tell(int nHandle);

int ddi_vfs_remove(const char *lpFileName);

int ddi_vfs_rename(const char *lpOldName, const char *lpNewName);

int ddi_vfs_filesize(const char *lpName);

int ddi_vfs_access(const char *lpName);

int ddi_vfs_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

int ddi_uart_open(uint32_t nCom, uint32_t baudrate);

int ddi_uart_close(uint32_t nCom);

int ddi_uart_read(uint32_t nCom, uint8_t *lpOut, uint32_t nLe);

int ddi_uart_write(uint32_t nCom, uint8_t *lpIn, uint32_t nLe);

int ddi_uart_ioctl(uint32_t nCom, uint32_t nCmd, uint32_t lParam, uint32_t WParam);

int ddi_lcd_open(void);

int ddi_lcd_close(void);

int ddi_lcd_clear_rect(const strRect *lpstrRect);

int ddi_lcd_show_text(uint32_t nX, uint32_t nY, const char *lpText);

int ddi_lcd_show_picture(const strRect *lpstrRect, const strPicture *lpstrPic);

int ddi_lcd_show_pixel_ex(uint32_t nX, uint32_t nY);

int ddi_lcd_show_line(const strLine *lpstrLine);

int ddi_lcd_show_rect(const strRect *lpstrRect);

void ddi_lcd_brush(const strRect *lpstrRect);

void ddi_lcd_brush_screen(void);

int ddi_lcd_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

int ddi_lcd_clear_screen(void);

int ddi_lcd_fill_row_ram(uint32_t nRow, uint32_t nCol, const char *lpText, uint32_t flag);

int ddi_lcd_clear_row(uint32_t nRow);

int ddi_lcd_get_text_width(const char *lpText);

int ddi_lcd_get_buffer_width(const char *lpText, int size);

int ddi_key_open(void);

int ddi_key_close(void);

int ddi_key_clear(void);

int ddi_key_read(uint32_t *lpKey);

int ddi_key_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

int ddi_bt_open(void);

int ddi_bt_close(void);

int ddi_bt_disconnect(void);

int ddi_bt_write(uint8_t *lpIn, uint32_t nLe);

int ddi_bt_read(uint8_t *lpOut, uint32_t nLe);

int ddi_bt_get_status(void);

int ddi_bt_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

int ddi_usb_open(void);

int ddi_usb_close(void);

int ddi_usb_read(uint8_t *lpOut, uint32_t nLe);

int ddi_usb_write(uint8_t *lpIn, uint32_t nLe);

int ddi_usb_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

int ddi_sec_tamper_cfg(void);

int ddi_sec_tamper_get_stat(void);

int ddi_sec_tamper_clr(void);

int ddi_sec_calc_sha1(uint8_t *pData, uint32_t dataLen, uint8_t *pHashValue);

int ddi_sec_calc_sha256(uint8_t *pData, uint32_t dataLen, uint8_t *pHashValue);

int ddi_sec_calc_md5(uint8_t *pData, uint32_t dataLen, uint8_t *pMd5Value);

int ddi_sec_get_randnum(uint8_t *pData, uint32_t dataLen);

int ddi_sec_get_cpuid(uint8_t *pData, int size);

int ddi_sec_rsa_sk_enc(uint8_t *pskey, uint8_t *pdata, uint32_t datalen, uint8_t *poutdata, uint32_t *poutlen);

int sec_reset_randkey(int op);

int sec_read_randkey(unsigned char result[32]);

int sec_sapi_command(unsigned char cmd, unsigned char inlen, const unsigned char *inbuf, unsigned char *outbuf);

int sec_read_vsn(unsigned char result[32]);

int sec_read_chipid(unsigned char result[32]);

int sec_ecdsa_verify_digest(int curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);

int sec_ecdsa_digital_sign(int curve, const uint8_t *pri_key, uint8_t *sig, const uint8_t *digest);

int ddi_sec_smgt_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

void ddi_soft_timer_start(uint16_t id, tmrMode mode, uint32_t delay, callback *cb, void *argv, uint16_t argc);

uint8_t ddi_soft_timer_get_state(uint16_t id);

int ddi_soft_timer_is_timeout(uint16_t id);

void ddi_soft_timer_stop(uint16_t id);

int ddi_flash_write(uint32_t addr, const uint8_t *data, uint32_t size);

int ddi_flash_read(uint32_t addr, uint8_t *data, uint32_t size);

int ddi_flash_sector_erase(uint32_t addr);

int ddi_flash_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

int ddi_ota_init(ota_file_info *ota_info);

int ddi_ota_write_img(uint32_t offset, uint8_t *pData, uint32_t len);

int ddi_ota_verify(void);

int ddi_ota_finish(void);

int ddi_ota_deinit(void);

int ddi_ota_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam);

int ddi_ota_prepare(void);

int ddi_ota_upgrade(void);

#endif
