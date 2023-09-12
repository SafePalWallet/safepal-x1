#include "plat_api.h"
#include "ex_sys.h"
#include "global.h"
#include "debug.h"
#include "libddi.h"

static ddi_sys_list_t gsys[1] = {0};
static ddi_flash_list_t flash[1] = {0};
static ddi_lcd_list_t lcd[1] = {0};
static ddi_key_list_t gkey[1] = {0};
static ddi_usb_list_t usb[1] = {0};
static ddi_uart_list_t uart[1] = {0};
static ddi_sec_list_t sec[1] = {0};
static ddi_bt_list_t bt[1] = {0};
static ddi_vfs_list_t vfs[1] = {0};
static ddi_mem_list_t mem[1] = {0};
static ddi_ota_list_t ota[1] = {0};
static ddi_soft_timer_list_t soft_timer[1] = {0};

static const ddi_cmd_item *ddi_cmd_items = NULL;
static const ddi_cmd_item *last_cmd_item = NULL;

static void *cmd_p(int n) {
    //if (!ddi_cmd_items) return NULL;
    const ddi_cmd_item *it;
    int i;
    //quickly query
    if (last_cmd_item) {
        for (i = 0, it = last_cmd_item + 1; (i < 3 && it->cmd != 0); i++, it++) { //try next 3
            if (it->cmd == n) {
                last_cmd_item = it;
                return it->p;
            }
        }
        for (i = 0, last_cmd_item - 1; (i < 3 && it > ddi_cmd_items); i++, it--) { //try back 3
            if (it->cmd == n) {
                last_cmd_item = it;
                return it->p;
            }
        }
    }
    //slow query
    for (it = ddi_cmd_items; it->cmd != 0; it++) {
        if (it->cmd == n) {
            last_cmd_item = it;
            return it->p;
        }
    }
    return NULL;
}

#define fetch_ddi_p(t, f)  t->f = cmd_p(ddi_id(f))

void init_ddi_item(const ddi_cmd_item *items) {
    if (!items) {
        return;
    }
    ddi_cmd_items = items;

    fetch_ddi_p(gsys, sys_msleep);
    fetch_ddi_p(gsys, sys_set_time);
    fetch_ddi_p(gsys, sys_get_time);
    fetch_ddi_p(gsys, sys_get_tick);
    fetch_ddi_p(gsys, sys_get_firmware_ver);
    fetch_ddi_p(gsys, sys_bat_status);
    fetch_ddi_p(gsys, sys_bat_vol);
    fetch_ddi_p(gsys, sys_poweroff);
    fetch_ddi_p(gsys, sys_poweroff);
    fetch_ddi_p(gsys, sys_reboot);
    fetch_ddi_p(gsys, sys_get_machtype);
    fetch_ddi_p(gsys, sys_cmd);

    fetch_ddi_p(flash, flash_write);
    fetch_ddi_p(flash, flash_read);
    fetch_ddi_p(flash, flash_ioctl);

    fetch_ddi_p(lcd, lcd_open);
    fetch_ddi_p(lcd, lcd_close);
    fetch_ddi_p(lcd, lcd_fill_rect);
    fetch_ddi_p(lcd, lcd_clear_rect);
    fetch_ddi_p(lcd, lcd_show_text);
    fetch_ddi_p(lcd, lcd_bmp_open);
    fetch_ddi_p(lcd, lcd_bmp_close);
    fetch_ddi_p(lcd, lcd_show_picture);
    fetch_ddi_p(lcd, lcd_show_pixel);
    fetch_ddi_p(lcd, lcd_show_pixel_ex);
    fetch_ddi_p(lcd, lcd_show_line);
    fetch_ddi_p(lcd, lcd_show_rect);
    fetch_ddi_p(lcd, lcd_extract_rect);
    fetch_ddi_p(lcd, lcd_brush);
    fetch_ddi_p(lcd, lcd_brush_screen);
    fetch_ddi_p(lcd, lcd_ioctl);
    fetch_ddi_p(lcd, lcd_clear_screen);
    fetch_ddi_p(lcd, lcd_fill_row_ram);
    fetch_ddi_p(lcd, lcd_clear_row);

    fetch_ddi_p(gkey, key_open);
    fetch_ddi_p(gkey, key_clear);
    fetch_ddi_p(gkey, key_read);
    fetch_ddi_p(gkey, key_ioctl);
    fetch_ddi_p(gkey, key_close);

    fetch_ddi_p(sec, tamper_cfg);
    fetch_ddi_p(sec, tamper_get_stat);
    fetch_ddi_p(sec, tamper_clr);
    fetch_ddi_p(sec, calc_sha1);
    fetch_ddi_p(sec, calc_sha256);
    fetch_ddi_p(sec, calc_md5);
    fetch_ddi_p(sec, get_randnum);
    fetch_ddi_p(sec, get_cpuid);
    fetch_ddi_p(sec, sec_rsa_sk_enc);
    fetch_ddi_p(sec, sec_reset_randkey);
    fetch_ddi_p(sec, sec_read_randkey);
    fetch_ddi_p(sec, sec_sapi_command);
    fetch_ddi_p(sec, sec_read_vsn);
    fetch_ddi_p(sec, sec_read_chipid);
    fetch_ddi_p(sec, sec_ecdsa_verify_digest);
    fetch_ddi_p(sec, sec_ecdsa_digital_sign);
    fetch_ddi_p(sec, sec_smgt_ioctl);

    fetch_ddi_p(bt, bt_open);
    fetch_ddi_p(bt, bt_close);
    fetch_ddi_p(bt, bt_disconnect);
    fetch_ddi_p(bt, bt_write);
    fetch_ddi_p(bt, bt_read);
    fetch_ddi_p(bt, bt_get_status);
    fetch_ddi_p(bt, bt_ioctl);

    fetch_ddi_p(usb, usb_open);
    fetch_ddi_p(usb, usb_close);
    fetch_ddi_p(usb, usb_read);
    fetch_ddi_p(usb, usb_write);
    fetch_ddi_p(usb, usb_ioctl);

    fetch_ddi_p(uart, uart_open);
    fetch_ddi_p(uart, uart_close);
    fetch_ddi_p(uart, uart_read);
    fetch_ddi_p(uart, uart_write);
    fetch_ddi_p(uart, uart_ioctl);

    fetch_ddi_p(mem, mem_malloc);
    fetch_ddi_p(mem, mem_free);
    fetch_ddi_p(mem, mem_realloc);

    fetch_ddi_p(vfs, vfs_mount);
    fetch_ddi_p(vfs, vfs_unmount);
    fetch_ddi_p(vfs, vfs_mkfs);
    fetch_ddi_p(vfs, vfs_open);
    fetch_ddi_p(vfs, vfs_close);
    fetch_ddi_p(vfs, vfs_write);
    fetch_ddi_p(vfs, vfs_read);
    fetch_ddi_p(vfs, vfs_seek);
    fetch_ddi_p(vfs, vfs_tell);
    fetch_ddi_p(vfs, vfs_remove);
    fetch_ddi_p(vfs, vfs_rename);
    fetch_ddi_p(vfs, vfs_access);
    fetch_ddi_p(vfs, vfs_ioctl);

    fetch_ddi_p(ota, ota_prepare);
    fetch_ddi_p(ota, ota_upgrade);
    fetch_ddi_p(ota, ota_ioctl);
	
    fetch_ddi_p(soft_timer, soft_timer_start);
    fetch_ddi_p(soft_timer, soft_timer_get_state);
    fetch_ddi_p(soft_timer, soft_timer_is_timeout);
    fetch_ddi_p(soft_timer, soft_timer_stop);
}

int ddi_sys_msleep(uint32_t nMs) {
    return gsys->sys_msleep(nMs);
}

int ddi_sys_set_time(const uint8_t *lpTime) {
    return gsys->sys_set_time(lpTime);
}

int ddi_sys_get_time(uint8_t *lpTime) {
    return gsys->sys_get_time(lpTime);
}

int ddi_sys_get_tick(uint32_t *time_ms) {
    return gsys->sys_get_tick(time_ms);
}

int ddi_sys_get_firmware_ver(uint8_t nType) {
    return gsys->sys_get_firmware_ver(nType);
}

int ddi_sys_bat_status(void) {
    return gsys->sys_bat_status();
}

int ddi_sys_bat_vol(void) {
    return gsys->sys_bat_vol();
}

int ddi_sys_poweroff(void) {
    return gsys->sys_poweroff();
}

int ddi_sys_reboot(void) {
    return gsys->sys_reboot();
}

int ddi_sys_get_machtype(void) {
    return gsys->sys_get_machtype();
}

int ddi_sys_cmd(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return gsys->sys_cmd(nCmd, lParam, wParam);
}

int ddi_flash_write(uint32_t addr, uint8_t *data, uint32_t size) {
    return flash->flash_write(addr, data, size);
}

int ddi_flash_read(uint32_t addr, uint8_t *data, uint32_t size) {
    return flash->flash_read(addr, data, size);
}

int ddi_flash_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return flash->flash_ioctl(nCmd, lParam, wParam);
}

int ddi_lcd_open(void) {
    return lcd->lcd_open();
}

int ddi_lcd_close(void) {
    return lcd->lcd_close();
}

int ddi_lcd_fill_rect(const strRect *lpstrRect, uint32_t nRGB) {
    return lcd->lcd_fill_rect(lpstrRect, nRGB);
}

int ddi_lcd_clear_rect(const strRect *lpstrRect) {
    return lcd->lcd_clear_rect(lpstrRect);
}

int ddi_lcd_show_text(uint32_t nX, uint32_t nY, const uint8_t *lpText) {
    return lcd->lcd_show_text(nX, nY, lpText);
}

int ddi_lcd_show_picture(const strRect *lpstrRect, const strPicture *lpstrPic) {
    return lcd->lcd_show_picture(lpstrRect, lpstrPic);
}

int ddi_lcd_show_pixel(uint32_t nX, uint32_t nY) {
    return lcd->lcd_show_pixel(nX, nY);
}

int ddi_lcd_show_pixel_ex(uint32_t nX, uint32_t nY) {
    return lcd->lcd_show_pixel_ex(nX, nY);
}

int ddi_lcd_show_line(const strLine *lpstrLine) {
    return lcd->lcd_show_line(lpstrLine);
}

int ddi_lcd_show_rect(const strRect *lpstrRect) {
    return lcd->lcd_show_rect(lpstrRect);
}

int ddi_lcd_extract_rect(const strRect *lpstrRect, strPicture *lpstrPic) {
    return lcd->lcd_extract_rect(lpstrRect, lpstrPic);
}

void ddi_lcd_brush(const strRect *lpstrRect) {
    return lcd->lcd_brush(lpstrRect);
}

void ddi_lcd_brush_screen(void) {
    return lcd->lcd_brush_screen();
}

int ddi_lcd_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return lcd->lcd_ioctl(nCmd, lParam, wParam);
}

strPicture *ddi_lcd_bmp_open(const char *lpBmpName) {
    return lcd->lcd_bmp_open(lpBmpName);
}

int ddi_lcd_bmp_close(strPicture *lpstrPic) {
    return lcd->lcd_bmp_close(lpstrPic);
}

int ddi_lcd_clear_screen(void) {
    return lcd->lcd_clear_screen();
}

int ddi_lcd_fill_row_ram(uint32_t nRow, uint32_t nCol, const char *lpText, uint32_t flag) {
    return lcd->lcd_fill_row_ram(nRow, nCol, lpText, flag);
}

int ddi_lcd_clear_row(uint32_t nRow) {
    return lcd->lcd_clear_row(nRow);
}

void DealPowerOff(void) {
    uint8_t key_ret;
    uint32_t key = 0;
    uint8_t i = 0;
    int selectitem = 0;
    int flag = 0;

    while (1) {
        if (!flag) {
            flag = 1;
            ddi_sys_cmd(SYS_CMD_POWEROFF_SCREEN, 1, selectitem + 1);
        }

        ddi_sys_msleep(50);
        i = ddi_key_read(&key);
        if (i > 0) {
            key_ret = (uint8_t) key;
            if (KEY_5 == key_ret) {
                flag = 0;
                selectitem--;
                if (selectitem < 0)
                    selectitem = 2;
            } else if (KEY_0 == key_ret) {
                flag = 0;
                selectitem++;
                if (selectitem > 2)
                    selectitem = 0;
            }

            if (KEY_ENTER == key_ret) {
                if (0 == selectitem) {
                    db_msg("ddi_sys_poweroff");
                    ddi_sys_poweroff();
                    break;
                } else if (1 == selectitem) {
                    db_msg("ddi_sys_reboot");
                    ddi_sys_reboot();
                    break;
                } else if (2 == selectitem) {
                    ddi_sys_cmd(SYS_CMD_EXIT_POWEROFF_SCREEN, 1, 1);
                    ddi_lcd_brush_screen();
                    break;
                }
            } else if (KEY_ESC == key_ret) {
                ddi_sys_cmd(SYS_CMD_EXIT_POWEROFF_SCREEN, 1, 1);
                ddi_lcd_brush_screen();
                break;
            }
        }
    }
}

int ddi_key_open(void) {
    return gkey->key_open();
}

int ddi_key_close(void) {
    return gkey->key_close();
}

int ddi_key_read(uint32_t *lpKey) {
    int ret = 0;

    ret = gkey->key_read(lpKey);
    if (ret > 0) {
        uint32_t time_ms = 0;
        ddi_sys_get_tick(&time_ms);
        /* hash * 33 + c */
        Global_Key_Random_Source = ((Global_Key_Random_Source << 5) + Global_Key_Random_Source) + *lpKey;
        if (time_ms) {
            Global_Key_Random_Source = ((Global_Key_Random_Source << 5) + Global_Key_Random_Source) + time_ms;
        }
        if (*lpKey == KEY_PWR) {
            ddi_sys_poweroff();
            //DealPowerOff();
        }
    }

    return ret;
}

int ddi_key_clear(void) {
    return gkey->key_clear();
}

int ddi_key_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return gkey->key_ioctl(nCmd, lParam, wParam);
}

int ddi_sec_tamper_cfg(void) {
    return sec->tamper_cfg();
}

int ddi_sec_tamper_get_stat(void) {
    return sec->tamper_get_stat();
}

int ddi_sec_tamper_clr(void) {
    return sec->tamper_clr();
}

int ddi_sec_calc_sha1(uint8_t *pData, uint32_t dataLen, uint8_t *pHashValue) {
    return sec->calc_sha1(pData, dataLen, pHashValue);
}

int ddi_sec_calc_sha256(uint8_t *pData, uint32_t dataLen, uint8_t *pHashValue) {
    return sec->calc_sha256(pData, dataLen, pHashValue);
}

int ddi_sec_calc_md5(uint8_t *pData, uint32_t dataLen, uint8_t *pMd5Value) {
    return sec->calc_md5(pData, dataLen, pMd5Value);
}

int ddi_sec_get_randnum(uint8_t *pData, uint32_t dataLen) {
    return sec->get_randnum(pData, dataLen);
}

int ddi_sec_get_chipid(uint8_t *pData, int size) {
    return sec->get_cpuid(pData, size);
}

int ddi_sec_rsa_sk_enc(uint8_t *pskey, uint8_t *pdata, uint32_t datalen, uint8_t *poutdata, uint32_t *poutlen) {
    return sec->sec_rsa_sk_enc(pskey, pdata, datalen, poutdata, poutlen);
}

int sec_reset_randkey(int op) {
    return sec->sec_reset_randkey(op);
}

int sec_read_randkey(unsigned char result[32]) {
    return sec->sec_read_randkey(result);
}

int sec_sapi_command(unsigned char cmd, unsigned char inlen, const unsigned char *inbuf, unsigned char *outbuf) {
    return sec->sec_sapi_command(cmd, inlen, inbuf, outbuf);
}

int sec_read_vsn(unsigned char result[32]) {
    return sec->sec_read_vsn(result);
}

int sec_read_chipid(unsigned char result[32]) {
    return sec->sec_read_chipid(result);
}

int sec_ecdsa_verify_digest(int curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest) {
    return sec->sec_ecdsa_verify_digest(curve, pub_key, sig, digest);
}

int sec_ecdsa_digital_sign(int curve, const uint8_t *pri_key, uint8_t *sig, const uint8_t *digest) {
    return sec->sec_ecdsa_digital_sign(curve, pri_key, sig, digest);
}

int ddi_sec_smgt_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return sec->sec_smgt_ioctl(nCmd, lParam, wParam);
}

int ddi_bt_open(void) {
    return bt->bt_open();
}

int ddi_bt_close(void) {
    return bt->bt_close();
}

int ddi_bt_read(uint8_t *lpOut, uint32_t nLe) {
    return bt->bt_read(lpOut, nLe);
}

int ddi_bt_write(uint8_t *lpIn, uint32_t nLe) {
    return bt->bt_write(lpIn, nLe);
}

int ddi_bt_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return bt->bt_ioctl(nCmd, lParam, wParam);
}

int ddi_bt_get_status(void) {
    return bt->bt_get_status();
}

int ddi_bt_disconnect(void) {
    return bt->bt_disconnect();
}

int ddi_usb_open() {
    return usb->usb_open();
}

int ddi_usb_close(void) {
    return usb->usb_close();
}

int ddi_usb_read(uint8_t *lpOut, uint32_t nLe) {
    return usb->usb_read(lpOut, nLe);
}

int ddi_usb_write(uint8_t *lpIn, uint32_t nLe) {
    return usb->usb_write(lpIn, nLe);
}

int ddi_usb_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return usb->usb_ioctl(nCmd, lParam, wParam);
}

int ddi_uart_open(uint32_t nCom, uint32_t baudrate) {
    return uart->uart_open(nCom, baudrate);
}

int ddi_uart_close(uint32_t nCom) {
    return uart->uart_close(nCom);
}

int ddi_uart_read(uint32_t nCom, uint8_t *lpOut, uint32_t nLe) {
    return uart->uart_read(nCom, lpOut, nLe);
}

int ddi_uart_write(uint32_t nCom, uint8_t *lpIn, uint32_t nLe) {
    return uart->uart_write(nCom, lpIn, nLe);
}

int ddi_uart_ioctl(uint32_t nCom, uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return uart->uart_ioctl(nCom, nCmd, lParam, wParam);
}

static uint32_t get_diff_tick(uint32_t cur_tick, uint32_t prior_tick) {
    if (cur_tick < prior_tick) {
        return (cur_tick + (~prior_tick));
    } else {
        return (cur_tick - prior_tick);
    }
}

int ddi_utils_stimer_query(uint32_t stimer, uint32_t timout_ms) {
    uint32_t time_ms = 0;

    ddi_sys_get_tick(&time_ms);
    if (get_diff_tick(time_ms, stimer) >= timout_ms) {
        return 1;
    } else {
        return 0;
    }
}

void *ddi_mem_malloc(uint32_t size) {
    return mem->mem_malloc(size);
}

void ddi_mem_free(void *ptr) {
    return mem->mem_free(ptr);
}

void *ddi_mem_realloc(void *ptr, uint32_t size) {
    return mem->mem_realloc(ptr, size);
}

int ddi_vfs_mount(const char *path) {
    return vfs->vfs_mount(path);
}

int ddi_vfs_unmount(const char *path) {
    return vfs->vfs_unmount(path);
}

int ddi_vfs_mkfs(const char *path) {
    return vfs->vfs_mkfs(path);
}

int ddi_vfs_open(const char *lpPath, const char *lpMode) {
    if (vfs->vfs_open == NULL) {
        return -403;
    }
    return vfs->vfs_open(lpPath, lpMode);
}

int ddi_vfs_close(int nHandle) {
    return vfs->vfs_close(nHandle);
}

int ddi_vfs_write(const uint8_t *lpData, int nLen, int nHandle) {
    return vfs->vfs_write(lpData, nLen, nHandle);
}

int ddi_vfs_read(uint8_t *lpData, int nLen, int nHandle) {
    return vfs->vfs_read(lpData, nLen, nHandle);
}

int ddi_vfs_seek(int nHandle, int nOffset, int nWhence) {
    return vfs->vfs_seek(nHandle, nOffset, nWhence);
}

int ddi_vfs_tell(int nHandle) {
    return vfs->vfs_tell(nHandle);
}

int ddi_vfs_remove(const char *lpFileName) {
    return vfs->vfs_remove(lpFileName);
}

int ddi_vfs_rename(const char *lpOldName, const char *lpNewName) {
    return vfs->vfs_rename(lpOldName, lpNewName);
}

int ddi_vfs_access(const char *lpName) {
    return vfs->vfs_access(lpName);
}

int ddi_vfs_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return vfs->vfs_ioctl(nCmd, lParam, wParam);
}

int ddi_ota_ioctl(uint32_t nCmd, uint32_t lParam, uint32_t wParam) {
    return ota->ota_ioctl(nCmd, lParam, wParam);
}

int ddi_ota_prepare(void) {
    return ota->ota_prepare();
}

int ddi_ota_upgrade(void) {
    return ota->ota_upgrade();
}

void ddi_soft_timer_start(uint16_t id, tmrMode mode, uint32_t delay, callback *cb, void *argv, uint16_t argc) {
    soft_timer->soft_timer_start(id, mode, delay, cb, argv, argc);
}

uint8_t ddi_soft_timer_get_state(uint16_t id) {
    return soft_timer->soft_timer_get_state(id);
}

int ddi_soft_timer_is_timeout(uint16_t id) {
    return soft_timer->soft_timer_is_timeout(id);
}

void ddi_soft_timer_stop(uint16_t id) {
    soft_timer->soft_timer_stop(id);
}

