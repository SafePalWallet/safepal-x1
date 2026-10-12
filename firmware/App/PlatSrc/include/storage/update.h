#ifndef _UPDATE_DATA_H_
#define _UPDATE_DATA_H_

#define INTERNAL_BOOT_ADDR                  (0)
#define INTERNAL_BOOT_SIZE                  (48*1024UL)

#define INTERNAL_UPDATE_ADDR                (INTERNAL_BOOT_ADDR+INTERNAL_BOOT_SIZE)//C000
#define INTERNAL_UPDATE_SIZE                (128*1024UL)

#define INTERNAL_OS_ADDR                    (INTERNAL_UPDATE_ADDR+INTERNAL_UPDATE_SIZE)//2C000
#define INTERNAL_OS_SIZE                    (256*1024UL)

#define INTERNAL_APP_ADDR                   (INTERNAL_OS_ADDR+INTERNAL_OS_SIZE)//6C000
#define INTERNAL_APP_SIZE                   (1056*1024UL)

#ifdef PRODUCT_TYPE_X1_R32
#define INTERNAL_RESOURCE_ADDR              (INTERNAL_APP_ADDR+INTERNAL_APP_SIZE)//174000
#define INTERNAL_RESOURCE_SIZE              (436*1024UL)

#define INTERNAL_TEMP_ADDR                  (INTERNAL_RESOURCE_ADDR + INTERNAL_RESOURCE_SIZE)//
#define INTERNAL_TEMP_SIZE                  (1300*1024UL)
#else
#define INTERNAL_RESOURCE_ADDR              (INTERNAL_APP_ADDR+INTERNAL_APP_SIZE)//174000
#define INTERNAL_RESOURCE_SIZE              (236*1024UL)

#define INTERNAL_TEMP_ADDR                  (INTERNAL_RESOURCE_ADDR + INTERNAL_RESOURCE_SIZE)//1AF000
#define INTERNAL_TEMP_SIZE                  (1500*1024UL)
#endif

#define INTERNAL_FS_ADDR                    (INTERNAL_TEMP_ADDR+INTERNAL_TEMP_SIZE)//326000
#define INTERNAL_FS_SIZE                    (800*1024UL)

#define INTERNAL_UPDATE_FLAG_ADDR           (INTERNAL_FS_ADDR+INTERNAL_FS_SIZE)//3EE000
#define INTERNAL_UPDATE_FLAG_SIZE           (4*1024UL)

#define INTERNAL_BT_INFO_ADDR               (INTERNAL_UPDATE_FLAG_ADDR+INTERNAL_UPDATE_FLAG_SIZE)//3EF000
#define INTERNAL_BT_INFO_SIZE               (4*1024UL)

#define INTERNAL_PRIVATE_DATA_ADDR          (INTERNAL_BT_INFO_ADDR+INTERNAL_BT_INFO_SIZE)//3F0000
#define INTERNAL_PRIVATE_DATA_SIZE          (32*1024UL)

#define UPDATE_NO_FILE                (-2)

typedef struct FILE_INFO_ST_{
	uint8_t identifier[12];	
	uint32_t file_type;		
	uint32_t file_ver;		
	uint32_t MCU_ver;		
	uint32_t Image_ver;	
	uint32_t load_addr;		
	uint32_t Code_Size;		
	uint32_t RW_Size;		
	uint32_t Image_CRC32;	
	uint8_t Customer_info[48];
    uint8_t Date[48]; 
    uint8_t Time[48]; 
	uint32_t area_size;
    uint8_t reserved[316];
	uint32_t ST_CRC32;		
} FILE_INFO_ST;

#endif


