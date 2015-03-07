/*XML file loading*/
#include <mxml.h>

#include "log.h"
#include "directory_tree.h"
#include "directory_tree_private.h"

struct xml_error xml_handle_node(struct d_tree *t, node_t tree_node, mxml_node_t *node);
struct xml_error d_tree_load_xml(struct d_tree *t, const char *filename)
{
	struct xml_error err;
	err.type = XML_SUCCESS;

	FILE *fp;
	mxml_node_t *tree;

	fp = fopen(filename, "r");
	if(fp == NULL)
	{
		LOG_ERR("failed to open xml file \"%s\"", filename);
		err.type = XML_FAILED_OPEN;
		return err;
	}

	tree = mxmlLoadFile(NULL, fp, MXML_TEXT_CALLBACK);
	fclose(fp);
	if(tree == NULL)
	{
		LOG_ERR("failed to load xml file \"%s\"", filename);
		err.type = XML_FAILED_OPEN;
		return err;
	}

	mxml_node_t *node = NULL;
	if(mxmlGetType(tree) == MXML_ELEMENT)
	{
		const char *name = mxmlGetElement(tree);
		if(strcmp(name, "fs") == 0)
			node = tree;
		else
			node = mxmlFindElement(tree, tree, "fs", NULL, NULL, MXML_DESCEND_FIRST);
	}

	if(node == NULL)
	{
		LOG_ERR("failed to find root element");
		err.type = XML_ROOT_NOT_FOUND;
		return err;
	}

	err = xml_handle_node(t, tree_get_root(t->m_tree), node);
	mxmlDelete(tree);
	return err;
}

bool convert_string_to_long(const char *string, long *dst)
{
	if(dst == NULL || string == NULL)
		return false;

	errno = 0;
	char *end;
	long tmp = strtol(string, &end, 10);
	if(errno != 0)
		return false;
	*dst = tmp;
	return true;
}

struct xml_error xml_handle_node(struct d_tree *t, node_t tree_node, mxml_node_t *node)
{
	struct xml_error err;
	err.type = XML_SUCCESS;

	mxml_node_t *cur_node = node;
	while(cur_node != NULL)
	{
		if(mxmlGetType(cur_node) == MXML_ELEMENT)
		{
			const char *name = mxmlGetElement(cur_node);
			int type = 0;
			if(strcmp(name, "directory") == 0)
				type = 1;
			else if(strcmp(name, "entry") == 0)
				type = 2;
			else if(strcmp(name, "fs") == 0)
				type = 3;

			if(type != 0)
			{
				if(type == 1) //directory
				{
					const char *prop = mxmlElementGetAttr(cur_node, "name");
					if(prop != NULL)
					{
						node_t child = tree_node_create(t->m_tree);
						tree_node_set_parent(t->m_tree, child, tree_node);
						tree_node_set_data(t->m_tree, child, (void *)t->m_num_nodes);
						t->m_num_nodes++;
						t->m_node_data = realloc(t->m_node_data, sizeof(*t->m_node_data)*t->m_num_nodes);

						struct node_data *n = &t->m_node_data[t->m_num_nodes-1];
						n->m_name = strdup(prop);
						n->m_type = NODE_FOLDER;
						t->m_num_dirs += 1;

						struct xml_error err = xml_handle_node(t, child, mxmlGetFirstChild(cur_node));
						if(err.type != XML_SUCCESS)
							return err;

					}
					else
						LOG_ERR("directory entry without name will be ignored");
				}
				else if(type == 2) //file or subdirectory
				{
					const char *prop = mxmlElementGetAttr(cur_node, "path");
					if(prop != NULL)
					{
						const char *rec = mxmlElementGetAttr(cur_node, "recursive");
						bool recursive = rec!=NULL?strcmp(rec,"true")==0:false;
						if(d_tree_add_path(t, tree_node, prop, recursive) != SUCCESS)
							LOG_ERR("failed to add \"%s\"", prop);
					}
					else
						LOG_ERR("file entry without path will be ignored");
				}
				else
				{
					long value;
					const char *oem_name = mxmlElementGetAttr(cur_node, "oem_name");
					if(oem_name != NULL && !d_tree_set_oem_name(t, oem_name))
					{
						LOG_ERR("failed to set oem name");
						err.type = XML_INVALID_ATTRIBUTE;
						return err;
					}
					const char *string = mxmlElementGetAttr(cur_node, "bytes_per_sector");
					if(string != NULL && (!convert_string_to_long(string, &value) || !d_tree_set_bytes_per_sector(t, value)))
					{
						LOG_ERR("failed to set bytes_per_sector");
						err.type = XML_INVALID_ATTRIBUTE;
						return err;
					}

					string = mxmlElementGetAttr(cur_node, "sectors_per_cluster");
					if(string != NULL && (!convert_string_to_long(string, &value) || !d_tree_set_sectors_per_cluster(t, value)))
					{
						LOG_ERR("failed to set bytes_per_sector");
						err.type = XML_INVALID_ATTRIBUTE;
						return err;
					}

					string = mxmlElementGetAttr(cur_node, "num_FATs");
					if(string != NULL && (!convert_string_to_long(string, &value) || !d_tree_set_num_FATs(t, value)))
					{
						LOG_ERR("failed to set number of FATs");
						err.type = XML_INVALID_ATTRIBUTE;
						return err;
					}

					string = mxmlElementGetAttr(cur_node, "num_root_entries");
					if(string != NULL && (!convert_string_to_long(string, &value) || !d_tree_set_root_entries(t, value)))
					{
						LOG_ERR("failed to set number of root directory entries");
						err.type = XML_INVALID_ATTRIBUTE;
						return err;
					}

					const char *type = mxmlElementGetAttr(cur_node, "type");
					if(type != NULL)
					{
						bool ok = false;
						if(strcmp(type, "FAT16") == 0)
							ok = d_tree_set_FAT_type(t, FAT16);
						else if(strcmp(type, "FAT32") == 0)
							ok = d_tree_set_FAT_type(t, FAT32);

						if(!ok)
						{
							LOG_ERR("invalid filesystem type");
							err.type = XML_INVALID_ATTRIBUTE;
							return err;
						}
					}
					const char *allow_unsupported_size = mxmlElementGetAttr(cur_node, "allow_unsupported_size");
					if(allow_unsupported_size != NULL)
					{
						if(strcmp(allow_unsupported_size, "true") == 0)
							d_tree_allow_unsupported_size(t, true);
						else if(strcmp(allow_unsupported_size, "false") == 0)
							d_tree_allow_unsupported_size(t, false);
						else
						{
							LOG_ERR("allow_unsupported_size must be \"true\" or \"false\"");
							err.type = XML_INVALID_ATTRIBUTE;
							return err;
						}
					}

					struct xml_error err = xml_handle_node(t, tree_node, mxmlGetFirstChild(cur_node));
					if(err.type != XML_SUCCESS)
						return err;
				}
			}
			else
				LOG_ERR("unknown element \"%s\" will be ignored", name);
		}
		cur_node = mxmlGetNextSibling(cur_node);
	}

	return err;
}
