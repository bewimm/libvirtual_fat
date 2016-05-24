#include "directory_tree.h"
#include "tree.h"
#include "log.h"
#include "directory_tree_private.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
//#include <iconv.h>
#include <dirent.h>
#include <assert.h>
#include <time.h>
#include <inttypes.h>


void d_tree_make_nodes(struct d_tree *t, const char *path);

struct d_tree *d_tree_create(void)
{
	struct d_tree *d = malloc(sizeof(struct d_tree));
	d->empty_string[0] = '\0';
	d->m_tree = tree_create();
	d->m_node_data = malloc(sizeof(*d->m_node_data));
	d->m_node_data[0].m_type = NODE_FOLDER;
	d->m_node_data[0].m_name = d->empty_string;
	d->m_node_data[0].m_directory.m_entries = NULL;
	d->m_node_data[0].m_directory.m_num_dir_entries = 0;
	d->m_num_nodes = 1;
	d->m_num_dirs = 0;
	d->fat = NULL;
	d->m_fat_length = 0;
	d->m_cluster_node = malloc(sizeof(node_t)*2);
	d->m_cluster_node[0] = d->m_cluster_node[1] = INVALID_NODE;
	d->m_num_clusters = 0;
	node_t root = tree_get_root(d->m_tree);
	tree_node_set_data(d->m_tree, root, (void *)0);

	d->boot.data = NULL;
	d->config.user_bytes_per_sector = false;
	d->config.user_fat_type = false;
	d->config.user_num_fats = false;
	d->config.user_num_root_entries = false;
	d->config.user_oem_name = false;
	d->config.user_sectors_per_cluster = false;
	d->config.allow_unsupported_size = false;

#ifdef DEBUG_BUILD
	d->m_tmp_dir = NULL;
#endif
	return d;
}

enum d_tree_error d_tree_add_object(struct d_tree *t, const char *path, bool recursive)
{
	if(t == NULL || path == NULL)
		return INVALID_INPUT;
	node_t node = tree_get_root(t->m_tree);
	return d_tree_add_path(t, node, path, recursive);
}

void d_tree_free(struct d_tree *t)
{
	for(size_t i=0; i<t->m_num_nodes; i++)
	{
		struct node_data *node = t->m_node_data+i;
		if(node->m_name != t->empty_string)
			free(node->m_name);
		if(node->m_type == NODE_FOLDER)
			free(node->m_directory.m_entries);
	}
	free(t->fat);
	free(t->m_cluster_node);
	free(t->m_node_data);
	free(t->boot.data);
	tree_free(t->m_tree);
	free(t);
}

void d_tree_reduce_common_parents(struct d_tree *t)
{
	LOG_ERR("NOT IMPLEMENTED");
}

struct conversion_data
{
	size_t cluster_size;
	uint64_t next_cluster;
	//iconv_t conv;
	uint8_t path_buf[512]; /*max filename length is 255*/
};

uint32_t d_tree_convert_to_fat_node(struct d_tree *t, node_t n, struct conversion_data *data, uint32_t parent_cluster);

void fat_set_cluster_value(uint8_t *fat, enum fstype type, uint64_t cluster, uint32_t value)
{
	assert(fat != NULL);
	switch(type)
	{
		case FAT16:
			((uint16_t *)fat)[cluster] = htole16(value);
			break;
		case FAT32:
			((uint32_t *)fat)[cluster] = htole32(value);
			break;
		default:
			LOG_ERR("BUG:invalid type");
	}
}

#define FAT_EOF 0x0FFFFFF8

enum d_tree_error d_tree_allocate_dir_entry_space(struct d_tree *t, node_t n);

enum d_tree_error d_tree_convert_to_fat(struct d_tree *t)
{

	enum d_tree_error err = d_tree_allocate_dir_entry_space(t, tree_get_root(t->m_tree));
	if(err != SUCCESS)
		return err;

	struct cluster_count_t cluster_count;

	for(size_t j=0; j<sizeof(cluster_count.count)/sizeof(cluster_count.count[0]); j++)
		cluster_count.count[j] = 0;

	for(size_t i=0; i<t->m_num_nodes; i++)
	{
		struct node_data *data = t->m_node_data+i;
		assert(data->m_type == NODE_FILE || data->m_type == NODE_FOLDER);
		off64_t size;
		if(data->m_type == NODE_FILE)
			size = data->m_file.m_size;
		else
			size = data->m_directory.m_num_dir_entries*sizeof(*data->m_directory.m_entries);

		for(size_t j=0; j<sizeof(cluster_count.count)/sizeof(cluster_count.count[0]); j++)
			cluster_count.count[j] += (size+bytes_per_cluster[j])/bytes_per_cluster[j]; //no -1 to reserve AT LEAST 1 cluster for each entry
	}

	err = create_bootsector(&t->boot, &t->config, &cluster_count);
	if(err != SUCCESS)
		return err;

	size_t cluster_size = t->config.bytes_per_sector*t->config.sectors_per_cluster;
	t->m_cluster_offset = t->config.fat_type == FAT16 ? (t->config.num_root_entries*sizeof(struct fat_dir_entry)+cluster_size-1)/cluster_size : 0;

	struct conversion_data data;
	/*data.conv = iconv_open("UTF-8", "UTF-16");
	if(data.conv == (iconv_t)-1)
	    LOG_ERR("iconv_open() failed");*/
	data.cluster_size = cluster_size;
	data.next_cluster = 2;
	node_t root = tree_get_root(t->m_tree);
	d_tree_convert_to_fat_node(t, root, &data, 0);

	switch(t->config.fat_type)
	{
		case FAT16:
			t->m_fat_length = sizeof(uint16_t)*t->config.cluster_count;
			break;
		case FAT32:
			t->m_fat_length = sizeof(uint32_t)*t->config.cluster_count;
			break;
		default:
			LOG_ERR("BUG: illegal FAT type");
			return BUG;
	}
	t->fat = realloc(t->fat, t->m_fat_length);
	memset(t->fat, 0, t->m_fat_length);

	fat_set_cluster_value(t->fat, t->config.fat_type, 0, 0xFFFFFFFF);
	fat_set_cluster_value(t->fat, t->config.fat_type, 1, 0xFFFFFFFF);

	for(uint64_t i=3; i<t->m_num_clusters-t->m_cluster_offset; i++)
	{
		size_t node_idx = i+t->m_cluster_offset;
		fat_set_cluster_value(t->fat, t->config.fat_type, i-1, i);
		if(t->m_cluster_node[node_idx-1] != t->m_cluster_node[node_idx])
			fat_set_cluster_value(t->fat, t->config.fat_type, i-1, FAT_EOF);
	}
	fat_set_cluster_value(t->fat, t->config.fat_type, t->m_num_clusters-t->m_cluster_offset-1, FAT_EOF);
	//iconv_close(data.conv);
	return SUCCESS;
}

#define DIRENT_MAX_CHARS 13 /*maximum number of characters per extended entry*/

uint8_t fat_chksum(const char *name)
{
	uint8_t sum = 0;
	for(size_t i=11; i!=0; i--)
		sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + (uint8_t)(*name++);
	return sum;
}

const char *find_extension(const char *in)
{
	const char *last_dot = in;
	const char *p = in;
	while(*p != '\0')
	{
		if(*p == '.')
			last_dot = p;
		p++;
	}
	return last_dot;
}

uint8_t replace_illegal_character(uint8_t c)
{
	/*0x22, 0x2A, 0x2B, 0x2C, 0x2E, 0x2F, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x5B, 0x5C, 0x5D, 0x7C*/
	const uint8_t replacement = '_';
	if(c>='a' && c<='z')
		return c+'A'-'a';
	if(c<=0x20 || /*0x20 is disallowed by convention*/
	   c==0x22 ||
	   (c>=0x2A && c<=0xC ) ||
	   c==0x2E ||
	   c==0x2F ||
	   (c>=0x3A && c<=0x3F) ||
	   (c>=0x5B && c<=0x5D) ||
	   c==0x7C)
		return replacement;
	return c;
}

char *base_name(char *path)
{
	char *s = strrchr (path, '/');
	return (s == NULL) ? path : ++s;
}

struct fat_dir_entry *handle_short_name_duplicates(struct fat_dir_entry *current,
                                                   struct fat_dir_entry *latest,
                                                   struct fat_dir_entry *first)
{
	while(latest >= first)
	{
		if((latest->attr & ATTR_LONG_NAME) == ATTR_LONG_NAME)
			goto next_iteration;
		int i, num_ext_start;
		for(i=0; i<3; i++)
			if(latest->ext[i] != current->ext[i])
				goto next_iteration;
		bool has_numeric_extension = true;
		for(i=7; i>1; i--)
		{
			if(latest->name[i]<'0' || latest->name[i]>'9')
				break;
		}
		num_ext_start = i+1;
		if(has_numeric_extension && latest->name[i--]!='~')
			has_numeric_extension = false;

		if(has_numeric_extension)
		{
			for(; i>=0; i--)
				if(latest->name[i] != current->name[i])
					goto next_iteration;
			int cur_count = 0;
			for(i=num_ext_start; i<8; i++)
				cur_count = cur_count*10+(latest->name[i]-'0');

			if(cur_count >= 999999)
			{
				LOG_ERR("invalid short counter value");
				cur_count = 999998;
			}
			char buf[8];
			int c = snprintf(buf, sizeof(buf), "%u",cur_count+1);
			char *num_ext = current->name+7-c;
			*num_ext++ = '~';
			for(i=0; i<c; i++)
				num_ext[i] = buf[i];
			return NULL;
		}
		else
		{
			int first_space=0;
			for(i=0; i<8; i++)
			{
				if(latest->name[i] != current->name[i])
					goto next_iteration;
				if(first_space == 0 && latest->name[i] == ' ')
					first_space=i;
			}
			first_space = min(first_space,6);
			if(first_space==0)
				first_space = 6;
			latest->name[first_space]='~';
			latest->name[first_space+1]='1';
			current->name[first_space]='~';
			current->name[first_space+1]='2';
			return latest;
		}

next_iteration: /*jump here if the name doesn't match*/
		latest--;
	}
	return NULL;
}

enum d_tree_error d_tree_allocate_dir_entry_space(struct d_tree *t, node_t n)
{
	size_t idx = (size_t)tree_node_get_data(t->m_tree, n);
	struct node_data *n_data = &t->m_node_data[idx];
	if(n_data->m_type == NODE_FILE)
		return SUCCESS;

	size_t num_dir_entries = 0;
	/*count the number of required entries*/
	for(size_t i=0; i<tree_node_get_num_children(t->m_tree, n); i++)
	{
		node_t child = tree_node_get_child(t->m_tree,n,i);
		size_t idx = (size_t)tree_node_get_data(t->m_tree, child);
		struct node_data *n_data = &t->m_node_data[idx];
		if(n_data->m_type == NODE_FILE)
		{
			char *name = strdup(n_data->m_name);
			char *base = base_name(name);
			/*??always use long filenames for files even if the name fits within a single entry??*/
			size_t entries = (strlen(base)+DIRENT_MAX_CHARS)/DIRENT_MAX_CHARS;
			num_dir_entries += entries+1;
			free(name);
		}
		else if(n_data->m_type == NODE_FOLDER)
		{
			size_t len = strlen(n_data->m_name);
			size_t entries = (len+DIRENT_MAX_CHARS)/DIRENT_MAX_CHARS;
			num_dir_entries += entries+1;
		}
		else
		{
			LOG_ERR("BUG: Unknown node type.");
			return BUG;
		}
	}

	if(n != tree_get_root(t->m_tree))
		num_dir_entries += 2; /*'..' and '.'*/
	struct fat_dir_entry *entries = malloc(sizeof(*entries)*num_dir_entries);
	if(entries == NULL)
		return NOT_ENOUGH_MEMORY;
	n_data->m_directory.m_entries = entries;
	n_data->m_directory.m_num_dir_entries = num_dir_entries;

	for(size_t i=0; i<tree_node_get_num_children(t->m_tree, n); i++)
	{
		node_t child = tree_node_get_child(t->m_tree,n,i);

		enum d_tree_error err = d_tree_allocate_dir_entry_space(t, child);
		if(err != SUCCESS)
			return err;
	}
	return SUCCESS;
}

uint32_t d_tree_convert_to_fat_node(struct d_tree *t, node_t n, struct conversion_data *data, uint32_t parent_cluster)
{
	size_t idx = (size_t)tree_node_get_data(t->m_tree, n);
	struct node_data *n_data = &t->m_node_data[idx];

	if(n_data->m_type == NODE_FILE) /*file clusters*/
	{
		size_t num_clusters = (n_data->m_file.m_size+data->cluster_size-1)/data->cluster_size;
		size_t cur_cluster = data->next_cluster;
		if(cur_cluster+num_clusters > t->m_num_clusters)
		{
			t->m_cluster_node = realloc(t->m_cluster_node, sizeof(node_t)*(cur_cluster+num_clusters));
			t->m_num_clusters = cur_cluster+num_clusters;
		}
		for(size_t i=0; i<num_clusters; i++)
		{
			assert(data->next_cluster < t->m_num_clusters);
			t->m_cluster_node[data->next_cluster] = n;
			data->next_cluster++;
		}
		return n_data->m_file.m_size == 0 ? t->m_cluster_offset : cur_cluster;
	}

	size_t cur_idx = 0;
	uint64_t cur_cluster = data->next_cluster;
	uint64_t num_clusters = (sizeof(struct fat_dir_entry)*n_data->m_directory.m_num_dir_entries+data->cluster_size-1)/data->cluster_size;
	struct fat_dir_entry *entries = n_data->m_directory.m_entries;
	if(t->m_cluster_offset != 0 && n == tree_get_root(t->m_tree))
		num_clusters = t->m_cluster_offset;
	if(num_clusters == 0)
		num_clusters = 1;

	if(cur_cluster+num_clusters >= t->m_num_clusters)
	{
		t->m_cluster_node = realloc(t->m_cluster_node, sizeof(node_t)*(cur_cluster+num_clusters));
		t->m_num_clusters = cur_cluster+num_clusters;
	}
	for(size_t i=0; i<num_clusters; i++)
	{
		assert(data->next_cluster < t->m_num_clusters);
		t->m_cluster_node[data->next_cluster] = n;
		data->next_cluster++;
	}

	if(n != tree_get_root(t->m_tree))
	{
		assert(cur_cluster >= t->m_cluster_offset && parent_cluster >= 2);
		size_t disk_cluster = cur_cluster-t->m_cluster_offset;
		if(parent_cluster == 2)
			parent_cluster = 0;
		else
			parent_cluster -= t->m_cluster_offset;
		struct fat_dir_entry *cur_entry = entries+cur_idx;
		memset(cur_entry, 0, sizeof(*cur_entry));
		strncpy(cur_entry->name, ".       ",8);
		strncpy(cur_entry->ext, "   ",3);
		cur_entry->attr = ATTR_RO | ATTR_DIR;
		cur_entry->starthi = htole16((disk_cluster&0xFFFF0000)>>16);
		cur_entry->start = htole16(disk_cluster&0x0000FFFF);
		cur_idx++;

		cur_entry = entries+cur_idx;
		memset(cur_entry, 0, sizeof(*cur_entry));
		strncpy(cur_entry->name, "..      ",8);
		strncpy(cur_entry->ext, "   ",3);
		cur_entry->attr = ATTR_RO | ATTR_DIR;
		cur_entry->starthi = htole16((parent_cluster&0xFFFF0000)>>16);
		cur_entry->start = htole16(parent_cluster&0x0000FFFF);
		cur_idx++;
	}

	for(size_t i=0; i<tree_node_get_num_children(t->m_tree, n); i++)
	{
		node_t child = tree_node_get_child(t->m_tree,n,i);
		size_t idx = (size_t)tree_node_get_data(t->m_tree, child);
		struct node_data *node_data = &t->m_node_data[idx];

		char *tmp_str = strdup(node_data->m_name);
		char zero = '\0';
		char *name = &zero;
		size_t num_long_entries = 1;

		if(node_data->m_type == NODE_FILE)
			name = base_name(tmp_str);
		else if(node_data->m_type == NODE_FOLDER)
			name = tmp_str;
		else
			LOG_ERR("BUG: Unknown node type.");

		if(2*strlen(name)>=sizeof(data->path_buf))
		{
			/*catching this error here is not ideal as it wastes a bit of space*/
			LOG_ERR("filenames may not be longer than 255 characters - skipping entry");
			free(tmp_str);
			continue;
		}

		num_long_entries = (strlen(name)+DIRENT_MAX_CHARS)/DIRENT_MAX_CHARS;

		uint8_t chksum;
		struct fat_dir_entry *short_entry;
		struct fat_dir_entry *cur_entry = short_entry = entries+cur_idx+num_long_entries;
		{
			/*short filename*/
			const char *ext = find_extension(name);
			memset(cur_entry, 0, sizeof(*cur_entry));
			char *dst = cur_entry->name;
			const char *p=name;
			for(; p<name+8 && (p!=ext || ext == name) && *p != '\0'; p++)
				*dst++ = replace_illegal_character(*p);
			for(; p<name+8; p++)
				*dst++ = ' ';

			dst = cur_entry->ext;
			if(ext != name && node_data->m_type == NODE_FILE)
			{
				for(p=ext+1; p<ext+4 && *p!='\0'; p++)
					*dst++ = replace_illegal_character(*p);
				for(; p<ext+4; p++)
					*dst++ = ' ';
			}
			else
			{
				for(size_t i=0; i<3; i++)
					*dst++ = ' ';
			}

			struct fat_dir_entry *found = handle_short_name_duplicates(cur_entry, entries+cur_idx-1, entries);

			if(found != NULL)
			{
				uint8_t new_chksum = fat_chksum(found->name);
				found--;
				while(found >= entries && (found->attr&ATTR_LONG_NAME)==ATTR_LONG_NAME)
				{
					uint8_t *dst = (uint8_t *)found;
					dst[13] = new_chksum;
					found--;
				}
			}

			chksum = fat_chksum(cur_entry->name);
			cur_entry->attr = ATTR_RO;

			if(node_data->m_type == NODE_FOLDER)
				cur_entry->attr |= ATTR_DIR;
			else
				cur_entry->size = htole32(node_data->m_file.m_size);

			cur_entry->ctime = node_data->m_modification_time;
			cur_entry->cdate = node_data->m_modification_date;
			cur_entry->ctime_ms = 0;
			cur_entry->adate = node_data->m_access_date;
			cur_entry->time = node_data->m_modification_time;
			cur_entry->date  = node_data->m_modification_date;
		}
		{
			/*long one*/
			size_t in_len = strlen(name), out_len=sizeof(data->path_buf);
			char *in = name, *out = (char *)data->path_buf;
			/*if(iconv(data->conv, &in, &in_len, &out, &out_len) == ((size_t)-1))
			    LOG_ERR("iconv() failed");
			if(out_len != sizeof(data->path_buf)-in_len*2)
			    LOG_ERR("BUG: UTF-8 -> UTF-16 failed.");*/
			out_len = sizeof(data->path_buf)-2*in_len;
			for(size_t i=0; i<in_len; i++)
			{
				out[i*2+0] = in[i];
				out[i*2+1] = 0;
			}

			const off_t offsets[26] = {1,2,3,4,5,6,7,8,9,10,14,15,16,17,18,19,20,21,22,23,24,25,28,29,30,31}; /*offsets in entry for UTF-16 characters (in bytes)*/
			uint8_t entry_count = 0;
			size_t cur_byte = 0;
			size_t total_bytes = sizeof(data->path_buf)-out_len;
			for(size_t i=0; i<num_long_entries; i++)
			{
				cur_entry--;
				entry_count++;
				memset(cur_entry, 0, sizeof(*cur_entry));
				cur_entry->name[0] = entry_count;
				if(i+1 == num_long_entries)
					cur_entry->name[0] |= 64; /*marker for last long entry*/

				uint8_t *dst = (uint8_t *)cur_entry;
				size_t j=0;
				for(; cur_byte<total_bytes && j<26; cur_byte++, j++)
					dst[offsets[j]] = data->path_buf[cur_byte];
				if(j<26 && cur_byte==total_bytes)
				{
					assert(j<25);
					dst[offsets[j]] = dst[offsets[j+1]] = 0;
					j+=2;
				}
				for(; j<26; j++)
					dst[offsets[j]] = 0xFF;
				dst[11] = ATTR_LONG_NAME;
				dst[12] = 0x00;
				dst[13] = chksum;
				dst[26] = dst[27] = 0x00;
			}
		}
		cur_idx += 1+num_long_entries;

		free(tmp_str);

		uint32_t cluster = d_tree_convert_to_fat_node(t, child, data, cur_cluster);
		assert(cluster >= t->m_cluster_offset);
		cluster -= t->m_cluster_offset;
		short_entry->starthi = htole16((cluster&0xFFFF0000)>>16);
		short_entry->start = htole16(cluster&0x0000FFFF);

	}
	return cur_cluster;
}

enum d_tree_error d_tree_get_cluster_content(struct d_tree *t, off64_t offset, size_t length, uint8_t *dst)
{
	const struct fat_config_t *config = &t->config;
	const off64_t fat_sector_end = config->num_reserved_sectors+config->num_fats*config->fat_size;
	const off64_t root_dir_sectors = (config->num_root_entries*sizeof(struct fat_dir_entry) +config->bytes_per_sector-1)/config->bytes_per_sector;
	const off64_t root_dir_sector_end = fat_sector_end + root_dir_sectors;
	const size_t cluster_size = config->bytes_per_sector*config->sectors_per_cluster;

	while(length>0)
	{
		size_t old_length = length;
		size_t cluster = (offset-root_dir_sector_end*config->bytes_per_sector)/cluster_size+t->m_cluster_offset;
		size_t in_cluster_offset = offset-root_dir_sector_end*config->bytes_per_sector-(cluster-t->m_cluster_offset)*cluster_size;
		cluster += 2;

		if(offset < config->num_reserved_sectors*config->bytes_per_sector)
		{
			size_t len = min(length, t->boot.len-offset);
			memcpy(dst, t->boot.data+offset, len);
			length -= len;
			dst += len;
			offset += len;
		}
		else if(offset < fat_sector_end*config->bytes_per_sector) /*FATs*/
		{
			off64_t fat_pos = offset-config->num_reserved_sectors*config->bytes_per_sector;
			while(fat_pos >= config->fat_size*config->bytes_per_sector) /*FATs are block aligned*/
				fat_pos -= config->fat_size*config->bytes_per_sector;
			if(fat_pos >= t->m_fat_length)
			{
				size_t len = min(config->fat_size*config->bytes_per_sector-fat_pos,length);
				memset(dst, 0, len);
				length -= len;
				dst += len;
				offset += len;
			}
			else
			{
				if(fat_pos >= t->m_fat_length)
					fat_pos -= t->m_fat_length;
				assert(t->m_fat_length>=fat_pos);
				size_t len = min(t->m_fat_length-fat_pos, length);
				memcpy(dst, t->fat+fat_pos, len);
				length -= len;
				dst += len;
				offset += len;
			}

		}
		else if(offset < root_dir_sector_end*config->bytes_per_sector)
		{
			node_t n = t->m_cluster_node[t->m_cluster_offset];
			size_t idx = (size_t)tree_node_get_data(t->m_tree,n);
			struct node_data *node = &t->m_node_data[idx];

			if(node->m_type != NODE_FOLDER)
			{
				LOG_ERR("BUG: entry for root directory is not a directory");
				return BUG;
			}

			size_t folder_len = node->m_directory.m_num_dir_entries*sizeof(*node->m_directory.m_entries);
			size_t folder_offset = offset-fat_sector_end*config->bytes_per_sector;
			size_t max_len = min(length, folder_len-folder_offset);

			if(folder_offset >= folder_len)
			{
				size_t root_dir_remainder = root_dir_sector_end*config->bytes_per_sector-offset;
				root_dir_remainder = min(root_dir_remainder, length);
				memset(dst, 0, root_dir_remainder);
				length -= root_dir_remainder;
				dst += root_dir_remainder;
				offset += root_dir_remainder;
			}
			else
			{
				uint8_t *src = (uint8_t *)node->m_directory.m_entries;
				memcpy(dst, src+folder_offset, max_len);
				length -= max_len;
				dst += max_len;
				offset += max_len;
			}

		}
		else if(cluster >= t->m_num_clusters) /*end of disk*/
		{
			assert(in_cluster_offset < cluster_size);
			memset(dst, 0, length);
			dst += length;
			offset += length;
			length = 0;
		}
		else /*file or folder cluster*/
		{
			assert(in_cluster_offset < cluster_size);
			node_t n = t->m_cluster_node[cluster];
			size_t idx = (size_t)tree_node_get_data(t->m_tree,n);
			struct node_data *node = &t->m_node_data[idx];

			size_t num_clusters = 0; /*for files/folders that span multiple clusters*/
			for(size_t i=cluster-1; t->m_cluster_node[i]==n; i--)
				num_clusters++;

			switch(node->m_type)
			{
				case NODE_FILE:
				{
					static node_t last_node = INVALID_NODE;
					static int last_file = -1;

					if(last_node != n)
					{
						if(last_file > 0)
							close(last_file);
						last_file = open(node->m_name, O_RDONLY|O_NOATIME|O_DIRECT);
						if(last_file == -1)
							LOG_ERR("failed to open file");
						else
							last_node = n;
					}

					off64_t file_offset = in_cluster_offset+(off64_t)num_clusters*cluster_size;

					if(last_file == -1 || file_offset >= node->m_file.m_size)
					{
						if(last_file == -1)
						{
							LOG_ERR("BUG: last_file==-1");
							return BUG;
						}
						size_t len = min(cluster_size-in_cluster_offset,length);
						memset(dst, 0, len);
						length -= len;
						dst += len;
						offset += len;
					}
					else
					{
						size_t max_len = min(length, node->m_file.m_size-file_offset);
						size_t read_bytes = pread64(last_file, dst, sizeof(uint8_t)*max_len, file_offset);
						if(read_bytes != max_len)
							LOG_ERR("file does not have the expected length");

						length -= max_len;
						dst += max_len;
						offset += max_len;
					}
				}
				break;
				case NODE_FOLDER:
				{
					size_t folder_len = node->m_directory.m_num_dir_entries*sizeof(*node->m_directory.m_entries);
					size_t folder_offset = in_cluster_offset+num_clusters*cluster_size;
					size_t max_len = min(length, folder_len-folder_offset);

					if(folder_offset >= folder_len)
					{
						size_t cluster_remainder = cluster_size-in_cluster_offset;
						cluster_remainder = min(cluster_remainder, length);
						memset(dst, 0, cluster_remainder);
						length -= cluster_remainder;
						dst += cluster_remainder;
						offset += cluster_remainder;
					}
					else
					{
						uint8_t *src = (uint8_t *)node->m_directory.m_entries;
						memcpy(dst, src+folder_offset, max_len);
						length -= max_len;
						dst += max_len;
						offset += max_len;
					}
				}
				break;
				default:
					LOG_ERR("unknown node type");
					return BUG;
			}
		}
		if(old_length <= length)
		{
			LOG_ERR("[BUG] infinite loop detected");
			return BUG;
		}
	}
	return SUCCESS;
}

void d_tree_print_node(struct d_tree *t, node_t n, size_t lvl)
{

	for(size_t i=1; i<lvl; i++)
		printf(" ");
	if(lvl>0)
		printf("+");
	size_t idx = (size_t)tree_node_get_data(t->m_tree, n);
	printf("%s [%c]\n", t->m_node_data[idx].m_name, t->m_node_data[idx].m_type==NODE_FILE?'F':'D');

	for(size_t i=0; i<tree_node_get_num_children(t->m_tree, n); i++)
		d_tree_print_node(t, tree_node_get_child(t->m_tree, n, i), lvl+1);

}

void d_tree_print(struct d_tree *t)
{
	printf("%"PRIu64" bytes in %zu folders\n", d_tree_get_size(t), d_tree_get_num_directories(t));
	d_tree_print_node(t, tree_get_root(t->m_tree), 0);
}

size_t d_tree_get_num_directories(struct d_tree *t)
{
	if(t == NULL)
		return 0;
	return t->m_num_dirs;
}

uint16_t tm_struct_to_fat_date(struct tm *time)
{
	uint16_t day = time->tm_mday<1?1:time->tm_mday>31?31:time->tm_mday;
	uint16_t month = time->tm_mon+1;
	month = month<1?1:month>12?12:month;
	uint16_t year = time->tm_year<80?0:time->tm_year-80;

	return htole16((year<<9) + (month<<5) + day);
}

uint16_t tm_struct_to_fat_time(struct tm *time)
{
	uint16_t sec = time->tm_sec >> 1;
	sec = sec>29?29:sec;
	uint16_t minutes = time->tm_min>59?59:time->tm_min;
	uint16_t hour = time->tm_hour>23?23:time->tm_hour;

	return htole16((hour<<11) + (minutes<<5) + sec);
}

enum d_tree_error d_tree_add_path(struct d_tree *t, node_t node, const char *path, bool recursive)
{
	char *full_path = realpath(path, NULL);
	if(full_path == NULL)
	{
		LOG_ERR("could not determine path of file \"%s\" (does the file exist?)",path);
		return INVALID_INPUT;
	}

	struct stat statbuf;
	if(stat(full_path,&statbuf)!=0)
		return STAT_FAILED;

	if(!S_ISREG(statbuf.st_mode) && !S_ISDIR(statbuf.st_mode))
		return INVALID_TYPE;

	char *entry_name = S_ISREG(statbuf.st_mode)?strdup(full_path):strdup(base_name(full_path));

	size_t num_children = tree_node_get_num_children(t->m_tree, node);
	node_t child  = INVALID_NODE;
	for(size_t i=0; i<num_children; i++)
	{
		child = tree_node_get_child(t->m_tree, node, i);
		size_t idx = (size_t)tree_node_get_data(t->m_tree, child); /*ugly cast from void* to size_t*/

		if(strcmp(t->m_node_data[idx].m_name, entry_name) == 0)
			break;
		else
			child = INVALID_NODE;
	}

	if(child == INVALID_NODE)
	{
		child = tree_node_create(t->m_tree);
		tree_node_set_parent(t->m_tree, child, node);
		tree_node_set_data(t->m_tree, child, (void *)t->m_num_nodes);
		t->m_num_nodes++;
		t->m_node_data = realloc(t->m_node_data, sizeof(*t->m_node_data)*t->m_num_nodes);

		struct node_data *n = &t->m_node_data[t->m_num_nodes-1];

		struct tm *mtime = localtime(&statbuf.st_mtime);
		n->m_modification_time = tm_struct_to_fat_time(mtime);
		n->m_modification_date = tm_struct_to_fat_date(mtime);
		struct tm *atime = localtime(&statbuf.st_atime);
		n->m_access_date = tm_struct_to_fat_date(atime);

		if(S_ISREG(statbuf.st_mode))
		{
			n->m_name = entry_name;
			n->m_file.m_size = statbuf.st_size;
			n->m_type = NODE_FILE;
		}
		else
		{
			n->m_name = entry_name;
			n->m_directory.m_entries = NULL;
			n->m_directory.m_num_dir_entries = 0;
			n->m_type = NODE_FOLDER;
			t->m_num_dirs += 1;
		}

	}

	if(S_ISDIR(statbuf.st_mode) && recursive)
	{
		DIR *d;
		d = opendir(full_path);
		if(d != NULL)
		{
			struct dirent *result;
			struct dirent dir;

			while(readdir_r(d, &dir, &result)==0 && result!=NULL)
			{
				if(strcmp(dir.d_name, ".")==0 || strcmp(dir.d_name, "..")==0)
					continue;
				size_t path_len = strlen(full_path);
				size_t file_len = strlen(dir.d_name);
				char *subentry = malloc(path_len+file_len+2); //+2 for '/' and '\0'
				strcpy(subentry, full_path);
				subentry[path_len] = '/';
				strcpy(subentry+path_len+1, dir.d_name);

				d_tree_add_path(t, child, subentry, recursive);

				free(subentry);
			}
			closedir(d);
		}
	}
	free(full_path);
	return SUCCESS;
}

off64_t d_tree_get_size(struct d_tree *t)
{
	struct fat_config_t *config = &t->config;
	off64_t total_sectors = config->num_reserved_sectors;
	total_sectors += (off64_t)config->num_fats*config->fat_size;
	total_sectors += (off64_t)config->cluster_count*config->sectors_per_cluster;
	total_sectors += (off64_t)config->num_root_entries*32/config->bytes_per_sector;

	return total_sectors*t->config.bytes_per_sector;
}

bool d_tree_set_oem_name(struct d_tree *t, const char *name)
{
	if(t == NULL)
		return false;
	if(name != NULL)
	{
		for(size_t i=0; i<sizeof(t->config.oem_name) && *name != '\0'; i++)
			t->config.oem_name[i] = *name++;
	}
	else
		t->config.user_oem_name = false;

	return t->config.user_oem_name;
}

bool d_tree_set_bytes_per_sector(struct d_tree *t, uint16_t value)
{
	if(t == NULL)
		return false;

	if(value == 512 || value == 1024 || value == 2048 || value == 4096)
	{
		t->config.bytes_per_sector = value;
		t->config.user_bytes_per_sector = true;
	}
	else
		t->config.user_bytes_per_sector = false;

	return t->config.user_bytes_per_sector;
}

bool d_tree_set_sectors_per_cluster(struct d_tree *t, uint8_t value)
{
	if(t == NULL)
		return false;

	if(value == 1 || value == 2 || value == 4 || value == 8 || value == 16 || value == 32 || value == 64 || value == 128)
	{
		t->config.sectors_per_cluster = value;
		t->config.user_sectors_per_cluster = true;
	}
	else
		t->config.user_sectors_per_cluster = false;

	return t->config.user_sectors_per_cluster;
}

bool d_tree_set_num_FATs(struct d_tree *t, uint8_t value)
{
	if(t == NULL)
		return false;

	if(value >= 1)
	{
		t->config.num_fats = value;
		t->config.user_num_fats = true;
	}
	else
		t->config.user_num_fats = false;

	return t->config.user_num_fats;
}

bool d_tree_set_root_entries(struct d_tree *t, uint16_t value)
{
	if(t == NULL)
		return false;

	if((value*32 & 511) == 0) /*number of root entries * 32 must be a multiple of the sector size. sector sizes other than 512 will be checked later*/
	{
		t->config.num_root_entries = value;
		t->config.user_num_root_entries = true;
	}
	else
		t->config.user_num_root_entries = false;
	return t->config.user_num_root_entries;
}

bool d_tree_set_FAT_type(struct d_tree *t, enum fstype type)
{
	if(t == NULL)
		return false;

	if(type == FAT16 || type == FAT32)
	{
		t->config.fat_type = type;
		t->config.user_fat_type = true;
	}
	else
		t->config.user_fat_type = false;

	return t->config.user_fat_type;
}

void d_tree_allow_unsupported_size(struct d_tree *t, bool allow)
{
	if(t == NULL)
		return;
	t->config.allow_unsupported_size = allow;
}


void set_temp_dir(struct d_tree *t, const char *path)
{
#ifdef DEBUG_BUILD
	t->m_tmp_dir = strdup(path);
#endif
}
