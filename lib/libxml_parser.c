/*XML file loading*/
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "directory_tree.h"
#include "directory_tree_private.h"
#include "log.h"

struct xml_error xml_handle_node(struct d_tree *t, node_t tree_node, xmlNode *node);
struct xml_error d_tree_load_xml(struct d_tree *t, const char *filename)
{
	struct xml_error err;
	err.type = XML_SUCCESS;
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;

	LIBXML_TEST_VERSION

	doc = xmlReadFile(filename, NULL, 0);
	if (doc == NULL)
	{
		LOG_ERR("failed to open xml file \"%s\"", filename);
		err.type = XML_FAILED_OPEN;
		return err;
	}

	root_element = xmlDocGetRootElement(doc);
	if(root_element == NULL)
	{
		LOG_ERR("root node not found");
		err.type = XML_ROOT_NOT_FOUND;
		return err;
	}
	err = xml_handle_node(t, tree_get_root(t->m_tree) , root_element->children);

	xmlFreeDoc(doc);
	xmlCleanupParser();

	return err;
}

struct xml_error xml_handle_node(struct d_tree *t, node_t tree_node, xmlNode *node)
{
	struct xml_error err;
	err.type = XML_SUCCESS;
	if(node == NULL)
	{
		LOG_ERR("node is NULL");
		err.type = XML_ROOT_NOT_FOUND;
		return err;
	}

	for (xmlNode *cur_node = node; cur_node != NULL; cur_node = cur_node->next)
	{
		if (cur_node->type == XML_ELEMENT_NODE)
		{
			int type = 0;
			if(strcmp((char *)cur_node->name, "directory") == 0)
				type = 1;
			else if(strcmp((char *)cur_node->name, "entry") == 0)
				type = 2;

			if(type != 0)
			{
				if(type == 1) /*directory*/
				{
					char *prop = (char *)xmlGetProp(cur_node, (xmlChar *)"name");
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

						struct xml_error err = xml_handle_node(t, child, cur_node->children);
						if(err.type != XML_SUCCESS)
							return err;

					}
					else
						LOG_ERR("directory entry without name will be ignored");
				}
				else /*file or subdirectory*/
				{
					char *prop = (char *)xmlGetProp(cur_node, (xmlChar *)"path");
					if(prop != NULL)
					{
						char *rec = (char *)xmlGetProp(cur_node, (xmlChar *)"recursive");
						bool recursive = rec!=NULL?strcmp(rec,"true")==0:false;
						if(d_tree_add_path(t, tree_node, prop, recursive) != SUCCESS)
							LOG_ERR("failed to add \"%s\"", prop);
					}
					else
						LOG_ERR("file entry without path will be ignored");
				}
			}
			else
				LOG_ERR("unknown element \"%s\" will be ignored", cur_node->name);

		}
	}
	return err;
}