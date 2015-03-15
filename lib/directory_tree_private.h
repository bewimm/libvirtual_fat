#ifndef H_DIRECTROY_TREE_PRIVATE
#define H_DIRECTROY_TREE_PRIVATE

#include <stdint.h>
#include <stdbool.h>

#include "tree.h"

#define ATTR_RO      1		/* read-only */
#define ATTR_HIDDEN  2		/* hidden */
#define ATTR_SYS     4		/* system */
#define ATTR_VOLUME  8		/* volume label */
#define ATTR_DIR     16		/* directory */
#define ATTR_ARCH    32		/* archived */
#define ATTR_LONG_NAME (ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOLUME)

struct fat_dir_entry
{
	char name[8], ext[3];       /* name and extension */
	uint8_t attr;               /* attribute bits */
	uint8_t lcase;              /* Case for base and extension */
	uint8_t ctime_ms;           /* Creation time, milliseconds */
	uint16_t ctime;             /* Creation time */
	uint16_t cdate;             /* Creation date */
	uint16_t adate;             /* Last access date */
	uint16_t starthi;           /* high 16 bits of first cl. (FAT32) */
	uint16_t time, date, start; /* time, date and first cluster */
	uint32_t size;              /* file size (in bytes) */
} __attribute__ ((packed));

enum content_type {NODE_FILE,NODE_FOLDER};
struct node_data
{
	enum content_type m_type;
	size_t m_cluster;
	char *m_name; /*name in case of directory, full filename otherwise*/
	/*time data*/
	uint16_t m_modification_time;
	uint16_t m_modification_date;
	uint16_t m_access_date;

	union
	{
		struct file_data
		{
			off64_t m_size;
			bool m_null;
		} m_file;
		struct directory_data
		{
			struct fat_dir_entry *m_entries;
			size_t m_num_dir_entries;
		} m_directory;
	};

};

struct fat_config_t
{
	uint8_t oem_name[8];
	bool user_oem_name;

	uint16_t bytes_per_sector;
	bool user_bytes_per_sector;

	uint8_t sectors_per_cluster;
	bool user_sectors_per_cluster;

	uint8_t num_fats;
	bool user_num_fats;

	uint16_t num_root_entries;
	bool user_num_root_entries;

	enum fstype fat_type;
	bool user_fat_type;

	bool allow_unsupported_size;

	//the following data will be set by create_bootsector()
	off64_t cluster_count;
	uint16_t num_reserved_sectors;
	off64_t fat_size;

};

struct boot_t
{
	size_t len;
	uint8_t *data;
};

struct d_tree
{
	struct tree_t *m_tree;
	struct node_data *m_node_data;
	size_t m_num_nodes;
	char empty_string[1];
	size_t m_num_dirs; /*number of dirctories in tree*/
	uint8_t *fat;
	size_t m_fat_length; /*in bytes*/

	node_t *m_cluster_node; /*node in tree for each the cluster*/
	uint64_t m_num_clusters;

	struct fat_config_t config;

	size_t m_cluster_offset; /*compensates for hardcoded root dir for FAT16*/
	struct boot_t boot;
};

#define min(x,y) ((x)<(y)?(x):(y))

enum d_tree_error d_tree_add_dummy(struct d_tree *t, node_t node, const char *name, off64_t size);
enum d_tree_error d_tree_add_path(struct d_tree *t, node_t node, const char *path, bool recursive);

char *base_name(char *path);

//POSSIBLE BYTES_PER_CLUSTER: 512,1024,2048,4096,8192,16384,32768,65536,131072,262144,524288
//65k+ are not officially supported
static const size_t bytes_per_cluster[] =
{
	512,1024,2048,4096,8192,16384,32768,65536,
	131072,262144,524288 //these are not really supported
};

struct cluster_count_t
{
	uint64_t count[11];
};


enum d_tree_error create_bootsector(struct boot_t *boot, struct fat_config_t *config, const struct cluster_count_t *cluster_info);

#endif
