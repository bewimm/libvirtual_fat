#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/fd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <dirent.h>

#include "directory_tree.h"

#define min(x,y) ((x)<(y)?(x):(y))


static const char fat_file[] = "/vfat";

struct d_tree *tree = NULL;
uint64_t file_size = 0;

static const char config_file[] = "/config";
char config_file_content[PATH_MAX];

static int virtualfs_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0)
	{
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	}
	else if (strcmp(path, fat_file) == 0)
	{
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = file_size;
	}
	else if (strcmp(path, config_file) == 0)
	{
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = sizeof(config_file_content);
	}
	else
		res = -ENOENT;

	return res;
}

#if FUSE_USE_VERSION >= 30
static int virtualfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off64_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
#else
static int virtualfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off64_t offset, struct fuse_file_info *fi)
#endif
{
	if(strcmp(path, "/") != 0)
		return -ENOENT;

#if FUSE_USE_VERSION >= 30
	filler(buf, ".", NULL, 0, flags);
	filler(buf, "..", NULL, 0, flags);
	filler(buf, fat_file + 1, NULL, 0, flags);
	filler(buf, config_file + 1, NULL, 0, flags);
#else
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, fat_file + 1, NULL, 0);
	filler(buf, config_file + 1, NULL, 0);
#endif

	return 0;
}

static int virtualfs_open(const char *path, struct fuse_file_info *fi)
{
	if(strcmp(path, fat_file) == 0)
		return 0;
	else if(strcmp(path, config_file) == 0)
	{
		/*if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;*/
		return 0;
	}

	return -ENOENT;
}

static int virtualfs_read(const char *path, char *buf, size_t size, off64_t offset, struct fuse_file_info *fi)
{
	if(strcmp(path, fat_file) == 0)
	{
		size_t total_size = size;
		if(d_tree_get_cluster_content(tree, offset, size, (uint8_t *)buf) != SUCCESS)
			exit(EXIT_FAILURE);
		return total_size;
	}
	else if(strcmp(path, config_file) == 0)
	{
		if(offset > sizeof(config_file_content))
			return 0;
		size_t len = min(sizeof(config_file_content)-offset,size);
		memcpy(buf, config_file_content+offset, len);
		return len;
	}

	return -ENOENT;
}

static int virtualfs_write(const char *path, const char *buf, size_t size, off64_t offset, struct fuse_file_info *fi)
{
	if(strcmp(path, fat_file) != 0)
		return -ENOENT;
#ifdef PRINT_WRITES
	printf("attempted write of length %zu at byte %ti\n", size, offset);

	uint8_t tmp[512];
	size_t copy_size = min(size,sizeof(tmp));
	virtualfs_read(path, (char *)tmp, copy_size, offset, fi);
	for(size_t i=0; i<copy_size; i++)
	{
		if((uint8_t)buf[i] != tmp[i])
			printf("difference at byte %zu 0x%x->0x%x\n",i, tmp[i], (uint8_t)buf[i]);
	}
#endif

	return size;
}

static struct fuse_operations virtualfs_operations =
{
	.getattr	= virtualfs_getattr,
	.readdir	= virtualfs_readdir,
	.open		= virtualfs_open,
	.read		= virtualfs_read,
	.write      = virtualfs_write,
};

#define die(str) do{fprintf(stderr, "%s\n", str); exit(EXIT_FAILURE);}while(0)

bool test_read_consistency(void)
{
	uint8_t *buf = malloc(sizeof(uint8_t)*file_size);
	int read_bytes = virtualfs_read(fat_file, (char *)buf, file_size, 0, NULL);
	if(read_bytes != file_size)
	{
		printf("requested file size != read size (%"PRIu64" != %i)\n",file_size, read_bytes);
		goto fail;
	}
	uint8_t *p=buf;
	for(size_t i=0; i<file_size; i++)
	{
		uint8_t b;
		int read_bytes = virtualfs_read(fat_file, (char *)&b, 1, 0, NULL);
		if(read_bytes != 1)
		{
			printf("failed to read byte %zu\n",i);
			goto fail;
		}
		if(*p != b)
		{
			printf("read at byte %zu differs\n",i);
			goto fail;
		}
	}

	free(buf);
	return true;
fail:
	free(buf);
	return false;
}

int save_debug_xml(const char *base, bool scramble)
{
	tree  = d_tree_create();
	struct xml_error err = d_tree_load_xml(tree, base);
	if(err.type != XML_SUCCESS)
	{
		fprintf(stderr, "failed to parse config file (%i)", err.type);
		d_tree_free(tree);
		return EXIT_FAILURE;
	}

	size_t len = strlen(base);
	char *tmp = alloca(len+2);
	memcpy(tmp, base, len);
	tmp[len+0] = 'd';
	tmp[len+1] = '\0';

	if(!d_tree_make_debug_xml(tree, tmp, scramble))
	{
		fprintf(stderr, "failed to save debug xml");
		d_tree_free(tree);
		return EXIT_FAILURE;
	}
	d_tree_free(tree);
	return EXIT_SUCCESS;
}

bool check_valid_mountpoint(const char *fuse_dir)
{
	DIR *fuse = opendir(fuse_dir);
	if(fuse == NULL)
	{
		if(errno == ENOTDIR)
		{
			fprintf(stderr, "mount point is not a directory");
			return false;
		}
		else if(errno == ENOENT)
		{
			mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
			if(mkdir(fuse_dir, mode) != 0)
			{
				fprintf(stderr, "failed to create mount directory");
				return false;
			}
			fuse = opendir(fuse_dir);
			if(fuse == NULL)
			{
				fprintf(stderr, "failed to open created mount directory");
				return false;
			}
			fprintf(stdout, "created fuse dir: %s with permissions %o", fuse_dir, mode);
		}
		else
		{
			fprintf(stderr, "failed to open mount directory");
			return false;
		}
	}

	int n=0;
	struct dirent *d;
	while ((d = readdir(fuse)) != NULL)
		if(++n > 2)
		{
			fprintf(stderr, "directory is not empty");
			closedir(fuse);
			return false;
		}
	closedir(fuse);
	return true;
}

int main(int argc, char *argv[])
{
	if(argc != 3)
		return EXIT_FAILURE;
	char *fs_config_file = argv[1];
	char *fuse_dir = argv[2];

	if(fs_config_file == NULL || fuse_dir == NULL)
		return EXIT_FAILURE;

	if(strcmp(fuse_dir, "nullx")==0)
		return save_debug_xml(fs_config_file, true);
	if(strcmp(fuse_dir, "null")==0)
		return save_debug_xml(fs_config_file, false);

	if(!check_valid_mountpoint(fuse_dir))
		goto fail_open;

	if(tree != NULL)
	{
		d_tree_free(tree);
		tree = NULL;
	}
	tree  = d_tree_create();
	struct xml_error err = d_tree_load_xml(tree, fs_config_file);
	if(err.type != XML_SUCCESS)
	{
		fprintf(stderr, "failed to parse config file (%i)", err.type);
		goto fail_d_tree;
	}

	//d_tree_print(tree);

	if(d_tree_convert_to_fat(tree) != SUCCESS)
	{
		fprintf(stderr, "failed to convert to fat file system");
		goto fail_d_tree;
	}

	file_size = d_tree_get_size(tree);

	char *fuse_argv[] = {"virtual_fat", "-o", "allow_other", "-s", fuse_dir}; //USE THIS ON ANDROID
	//char *fuse_argv[] = {"virtual_fat", "-f", "-s", fuse_dir}; //USE THIS FOR DEBUGGING
	int fuse_argc = sizeof(fuse_argv)/sizeof(*fuse_argv);

	strncpy(config_file_content, fs_config_file, sizeof(config_file_content));
	if(fuse_main(fuse_argc, fuse_argv, &virtualfs_operations, NULL) != EXIT_SUCCESS)
	{
		fprintf(stderr, "fuse_main returned an error code");
		goto fail_d_tree;
	}

	return EXIT_SUCCESS;

fail_d_tree:
	d_tree_free(tree);
	tree = NULL;
fail_open:
	return EXIT_FAILURE;
}
