#ifndef H_DIRECTORY_TREE
#define H_DIRECTORY_TREE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>


struct d_tree;

enum d_tree_error {SUCCESS, INVALID_INPUT, STAT_FAILED, INVALID_TYPE, BUG, FAT_NOT_VALID, NOT_ENOUGH_MEMORY};

struct d_tree *d_tree_create(void);
void d_tree_free(struct d_tree *t);

void d_tree_reduce_common_parents(struct d_tree *t);
enum d_tree_error d_tree_convert_to_fat(struct d_tree *t);
enum d_tree_error d_tree_get_cluster_content(struct d_tree *t, off64_t offset, size_t length, uint8_t *dst);
void d_tree_print(struct d_tree *t);

size_t d_tree_get_num_directories(struct d_tree *t);

/*this function adds files/folders to the tree structure
  keep in mind that this:
    d_tree_add_object(tree, "./folder/", true);
    d_tree_add_object(tree, "./folder/file.txt", true);
  will result in the root directory looking as follows:
  +folder
  +-file.txt
  +-file2.txt
  +-[etc]
  +file.txt
  the file "file.txt" will be in the subfolder as well as in the root directory.
*/
enum d_tree_error d_tree_add_object(struct d_tree *t, const char *path, bool recursive);

/*load from file(s)*/
enum xml_error_type {XML_SUCCESS = 0, XML_FAILED_OPEN, XML_ROOT_NOT_FOUND, XML_INVALID_ATTRIBUTE};
struct xml_error
{
	enum xml_error_type type;
	int line;
};

struct xml_error d_tree_load_xml(struct d_tree *t, const char *filename);

enum d_tree_error d_tree_convert_to_fat(struct d_tree *t);

off64_t d_tree_get_size(struct d_tree *t);

enum fstype {AUTO=0, FAT16, FAT32};

bool d_tree_set_oem_name(struct d_tree *t, const char *name);
bool d_tree_set_bytes_per_sector(struct d_tree *t, uint16_t value);
bool d_tree_set_sectors_per_cluster(struct d_tree *t, uint8_t value);
bool d_tree_set_num_FATs(struct d_tree *t, uint8_t value);
bool d_tree_set_root_entries(struct d_tree *t, uint16_t value);
bool d_tree_set_FAT_type(struct d_tree *t, enum fstype type);
void d_tree_allow_unsupported_size(struct d_tree *t, bool allow);

#endif
