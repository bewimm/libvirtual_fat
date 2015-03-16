#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <endian.h>

#include "directory_tree.h"
#include "directory_tree_private.h"
#include "log.h"

struct volume_info
{
	uint8_t drive_number;
	uint8_t reserved1;
	uint8_t boot_signature;
	uint8_t volume_id[4];
	uint8_t volume_label[11];
	uint8_t fs_type[8];
} __attribute__ ((packed));

#define BOOTCODE_FAT16_SIZE	448
#define BOOTCODE_FAT32_SIZE	420

struct boot_sector
{
	uint8_t jmp_boot[3];
	uint8_t oem_name[8];
	uint16_t bytes_per_sector;
	uint8_t sectors_per_cluster;
	uint16_t num_reserved_sectors;
	uint8_t num_fats;
	uint16_t num_root_entries;
	uint16_t num_sectors_16;
	uint8_t media;
	uint16_t fat_size_16;
	uint16_t sectors_per_track;
	uint16_t num_heads;
	uint32_t num_hidden_sectors;
	uint32_t num_sectors_32;
	union
	{
		struct
		{
			struct volume_info vi;
			uint8_t boot_code[BOOTCODE_FAT16_SIZE];
		} __attribute__ ((packed)) fat_16; /*technically also FAT12 but I don't care about that*/
		struct
		{
			uint32_t fat_size_32;
			uint16_t flags;
			uint16_t version;
			uint32_t root_cluster_idx;
			uint16_t info_sector;
			uint16_t backup_boot;
			uint8_t reserved2[12];
			struct volume_info vi;
			uint8_t boot_code[BOOTCODE_FAT32_SIZE];
		} __attribute__ ((packed)) fat_32;
	} __attribute__ ((packed)) fstype;
	uint16_t boot_magic; /*0xAA55*/
} __attribute__ ((packed));


/*copied from a disk*/
uint8_t BOOT_CODE[BOOTCODE_FAT16_SIZE] =
    "\x0E\x1F\xBE\x5B\x7C\xAC\x22\xC0"
    "\x74\x0B\x56\xB4\x0E\xBB\x07\x00"
    "\xCD\x10\x5E\xEB\xF0\x32\xE4\xCD"
    "\x16\xCD\x19\xEB\xFE"
    "This is not a bootable disk.  Please insert a bootable floppy and\r\n"
    "press any key to try again ... \r\n";


typedef size_t (*termination_handler)(uint64_t num_cluster);

static size_t check_FAT16(uint64_t num_cluster)
{
	if(num_cluster < 4085)
		return 4085;
	else if(num_cluster < 65527)
		return num_cluster;
	return 0;
}

static size_t check_FAT32(uint64_t num_cluster)
{
	/* https://technet.microsoft.com/en-us/library/cc938438.aspx
	   the FAT must not be greater than (16MB-64KB)/4 */
	if(num_cluster > 4177920)
		return 0;
	if(num_cluster < 65527)
		return 65527;
	else
		return num_cluster;
}

enum d_tree_error try_make_fat(struct fat_config_t *config, const struct cluster_count_t *cluster_info, termination_handler func)
{
	size_t sector_size_start = 512, sector_size_end = 4096;
	size_t sec_per_cluster_start = 1, sec_per_cluster_end = 128;
	uint64_t fat_size = (size_t)-1;

	if(config->user_bytes_per_sector)
		sector_size_start = sector_size_end = config->bytes_per_sector;
	if(config->user_sectors_per_cluster)
		sec_per_cluster_start = sec_per_cluster_end = config->sectors_per_cluster;

	for(size_t sector_size = sector_size_start; sector_size<=sector_size_end; sector_size<<=1)
	{
		for(size_t sec_per_cluster = sec_per_cluster_start; sec_per_cluster<=sec_per_cluster_end; sec_per_cluster<<=1)
		{
			size_t cur_cluster_size = sector_size*sec_per_cluster;

			if(!config->allow_unsupported_size && cur_cluster_size > 32768)
				continue;

			size_t cluster_index = (size_t)-1;
			for(size_t i=0; i<sizeof(bytes_per_cluster)/sizeof(*bytes_per_cluster); i++)
			{
				if(bytes_per_cluster[i] == cur_cluster_size)
				{
					cluster_index = i;
					break;
				}
			}
			if(cluster_index == (size_t)-1)
			{
				LOG_ERR("[BUG] could not find cluster size");
				return BUG;
			}

			fat_size = cluster_info->count[cluster_index]+2;

			fat_size = func(fat_size);
			if(fat_size > 0)
			{
				config->cluster_count = fat_size;
				config->bytes_per_sector = sector_size;
				config->sectors_per_cluster = sec_per_cluster;
				return SUCCESS;
			}
		}
	}
	return FAT_NOT_VALID; /*exhausted all allowed combinations of sector and cluster size*/
}

enum d_tree_error try_make_fat16(struct fat_config_t *config, const struct cluster_count_t *cluster_info)
{
	return try_make_fat(config, cluster_info, check_FAT16);
}

enum d_tree_error try_make_fat32(struct fat_config_t *config, const struct cluster_count_t *cluster_info)
{
	return try_make_fat(config, cluster_info, check_FAT32);
}

#ifdef __ANDROID__
#define le16toh(x) letoh16(x)
#endif

enum d_tree_error create_bootsector(struct boot_t *boot, struct fat_config_t *config, const struct cluster_count_t *cluster_info)
{

	struct boot_sector tmp;
	struct boot_sector *bs = &tmp;
	memset(bs, 0, sizeof(*bs));

	bs->jmp_boot[0] = 0xEB;
	bs->jmp_boot[1] = 0x3C;
	bs->jmp_boot[2] = 0x90;

	if(!config->user_oem_name)
		memcpy(config->oem_name, "MSWIN4.1", sizeof(config->oem_name));

	const char *p = config->oem_name;
	for(size_t i=0; i<sizeof(bs->oem_name) && *p!='\0'; i++)
		bs->oem_name[i] = *p++;

	if(!config->user_bytes_per_sector)
		config->bytes_per_sector = 512;
	bs->bytes_per_sector = htole16(config->bytes_per_sector);

	if(!config->user_sectors_per_cluster)
		config->sectors_per_cluster = 1;
	bs->sectors_per_cluster = config->sectors_per_cluster;

	if(config->user_fat_type)
	{
		if(config->fat_type == FAT16)
		{
			if(try_make_fat16(config, cluster_info) != SUCCESS)
			{
				LOG_ERR("failed to create FAT16 filesystem (user input)");
				return INVALID_INPUT;
			}
			else
				config->fat_type = FAT16;
		}
		else if(config->fat_type == FAT32)
		{
			if(try_make_fat32(config, cluster_info) != SUCCESS)
			{
				LOG_ERR("failed to create FAT32 filesystem (user input)");
				return INVALID_INPUT;
			}
			else
				config->fat_type = FAT32;
		}
		else
		{
			LOG_ERR("invalid FAT type");
			return INVALID_INPUT;
		}
	}
	else
	{
		if(try_make_fat16(config, cluster_info) != SUCCESS)
		{
			if(try_make_fat32(config, cluster_info) != SUCCESS)
			{
				LOG_ERR("failed determine appropriate FAT type");
				return FAT_NOT_VALID;
			}
			else
				config->fat_type = FAT32;
		}
		else
			config->fat_type = FAT16;
	}

	assert(config->fat_type == FAT16 || config->fat_type == FAT32);

	bs->bytes_per_sector = htole16(config->bytes_per_sector);
	bs->sectors_per_cluster = config->sectors_per_cluster;

	if(!config->user_num_fats)
		config->num_fats = 2;

	bs->num_fats = config->num_fats;

	if(config->fat_type == FAT16)
	{
		if(!config->user_num_root_entries)
			config->num_root_entries = 512;
	}
	else
		config->num_root_entries = 0;

	if(config->num_root_entries*sizeof(struct fat_dir_entry)%config->bytes_per_sector != 0)
	{
		LOG_ERR("root directory size is not a multiple of the sector size");
		return FAT_NOT_VALID;
	}
	bs->num_root_entries = htole16(config->num_root_entries);

	struct volume_info *vi;

	if(config->fat_type == FAT16)
	{
		bs->jmp_boot[1] = offsetof(struct boot_sector, fstype.fat_16.boot_code);
		vi = &bs->fstype.fat_16.vi;
		config->num_reserved_sectors = 1;
		memcpy(vi->fs_type, "FAT16   ", sizeof(vi->fs_type));
		bs->num_reserved_sectors = htole16(config->num_reserved_sectors);
		config->fat_size = (config->cluster_count*sizeof(uint16_t)+config->bytes_per_sector-1)/config->bytes_per_sector;
		size_t total_sectors = config->num_reserved_sectors+config->num_fats*config->fat_size+config->cluster_count*config->sectors_per_cluster;
		total_sectors += config->num_root_entries*sizeof(struct fat_dir_entry)/config->bytes_per_sector;
		if(total_sectors >= 1<<16)
		{
			bs->num_sectors_16 = 0;
			bs->num_sectors_32 = htole32(total_sectors);
		}
		else
		{
			bs->num_sectors_16 = htole16(total_sectors);
			bs->num_sectors_32 = 0;
		}
		bs->fat_size_16 = htole16(config->fat_size);
		memcpy(bs->fstype.fat_16.boot_code, BOOT_CODE, BOOTCODE_FAT16_SIZE);
	}
	else
	{
		bs->jmp_boot[1] = offsetof(struct boot_sector, fstype.fat_32.boot_code);
		vi = &bs->fstype.fat_32.vi;
		memcpy(vi->fs_type, "FAT32   ", sizeof(vi->fs_type));
		config->num_reserved_sectors = 32;
		bs->num_reserved_sectors = htole16(config->num_reserved_sectors);
		bs->num_sectors_16 = 0;
		config->fat_size = (config->cluster_count*sizeof(uint32_t)+config->bytes_per_sector-1)/config->bytes_per_sector;
		bs->num_sectors_32 = htole32(config->num_reserved_sectors+config->num_fats*config->fat_size+config->cluster_count*config->sectors_per_cluster);
		bs->fat_size_16 = 0;
		bs->fstype.fat_32.fat_size_32 = htole32(config->fat_size);
		bs->fstype.fat_32.flags = 0;
		bs->fstype.fat_32.version = 0;
		bs->fstype.fat_32.root_cluster_idx = htole32(2);
		bs->fstype.fat_32.info_sector = htole16(1);
		bs->fstype.fat_32.backup_boot = config->num_reserved_sectors>=7 ? htole16(6) : config->num_reserved_sectors>=2 ? htole16(config->num_reserved_sectors-1) : 0;
		memcpy(bs->fstype.fat_32.boot_code, BOOT_CODE, BOOTCODE_FAT32_SIZE);
	}

	vi->boot_signature = 0x29;
	vi->drive_number = 0x80;
	//vi->volume_id = TODO
	//vi->volume_label = TODO;

	bs->media = 0xF8;
	bs->sectors_per_track = htole16(32);
	bs->num_heads = htole16(64);
	bs->num_hidden_sectors = 0;
	bs->boot_magic = htole16(0xAA55);

	boot->len = config->num_reserved_sectors*config->bytes_per_sector;
	boot->data = calloc(boot->len, sizeof(uint8_t));

	memcpy(boot->data, bs, sizeof(*bs));

	if(config->fat_type == FAT32)
	{
		size_t info_sector_offset = le16toh(bs->fstype.fat_32.info_sector)*config->bytes_per_sector;
		uint32_t *info_sector = (uint32_t *)(boot->data+info_sector_offset);

		*(info_sector+000) = htole32(0x41615252); //FSI_LeadSig
		*(info_sector+121) = htole32(0x61417272); //FSI_StrucSig
		*(info_sector+122) = htole32(0xFFFFFFFF); //free cluster count
		*(info_sector+123) = htole32(0xFFFFFFFF); //next free cluster
		*(info_sector+127) = htole32(0xAA550000); //FSI_TrailSig

		size_t backup_boot = le16toh(bs->fstype.fat_32.backup_boot)*config->bytes_per_sector;

		if(backup_boot != 0)
			memcpy(boot->data+backup_boot, bs, sizeof(*bs));
	}

	return SUCCESS;
}


