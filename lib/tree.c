#include "tree.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_SIZE 16
#define GROWTH_FACTOR 2

struct node_internal
{
	void *m_data;
	node_t m_parent;
	node_t *m_children;
	size_t m_num_children;
};

struct tree_t
{
	node_t m_root;
	struct node_internal *m_nodes;
	size_t m_num_nodes;
	size_t m_max_num_nodes;
};


struct tree_t *tree_create(void)
{
	struct tree_t *t = malloc(sizeof(struct tree_t));
	t->m_num_nodes = 0;
	t->m_max_num_nodes = INITIAL_SIZE;
	t->m_nodes = malloc(sizeof(struct node_internal)*t->m_max_num_nodes);
	t->m_root = tree_node_create(t);
	return t;
}

node_t tree_get_root(struct tree_t *t)
{
	if(t == NULL)
		return INVALID_NODE;
	return t->m_root;
}

node_t tree_node_create(struct tree_t *t)
{
	if(t->m_num_nodes >= t->m_max_num_nodes)
	{
		t->m_max_num_nodes = t->m_max_num_nodes*GROWTH_FACTOR;
		t->m_nodes = realloc(t->m_nodes, t->m_max_num_nodes*sizeof(struct node_internal));
	}

	node_t n = t->m_num_nodes;
	t->m_num_nodes++;

	t->m_nodes[n].m_parent = INVALID_NODE;
	t->m_nodes[n].m_children = NULL;
	t->m_nodes[n].m_data = NULL;
	t->m_nodes[n].m_num_children = 0;

	return n;
}

void tree_node_free(struct tree_t *t, node_t n)
{
	if(t==NULL || n == INVALID_NODE  || n>=t->m_num_nodes)
		return;

	struct node_internal *actual_node = &t->m_nodes[n];
	tree_node_unlink_child(t,n);
	free(actual_node->m_children);
	actual_node->m_children = NULL;
	actual_node->m_num_children = 0;
	t->m_num_nodes--;
	memmove(actual_node, actual_node+1, (t->m_num_nodes-n)*sizeof(*actual_node));
}

void tree_node_set_data(struct tree_t *t, node_t n, void *d)
{
	if(t==NULL || n == INVALID_NODE  || n>=t->m_num_nodes)
		return;
	t->m_nodes[n].m_data = d;
}

void tree_node_set_parent(struct tree_t *t, node_t child, node_t parent)
{
	if(t == NULL || child == INVALID_NODE || parent == INVALID_NODE)
		return;
	if(child>=t->m_num_nodes || parent>=t->m_num_nodes)
		return;

	tree_node_unlink_child(t, child);

	struct node_internal *parent_actual = &t->m_nodes[parent];

	parent_actual->m_children = realloc(parent_actual->m_children, sizeof(node_t)*(parent_actual->m_num_children+1));
	parent_actual->m_children[parent_actual->m_num_children] = child;
	parent_actual->m_num_children++;

	t->m_nodes[child].m_parent = parent;

}

void tree_node_unlink_child(struct tree_t *t, node_t child)
{
	if(t == NULL || child == INVALID_NODE)
		return;
	if(child>=t->m_num_nodes)
		return;
	node_t parent = t->m_nodes[child].m_parent;
	if(parent == INVALID_NODE || parent>=t->m_num_nodes)
		return;

	struct node_internal *parent_actual = &t->m_nodes[parent];
	t->m_nodes[child].m_parent = INVALID_NODE;
	for(size_t i=0; i<parent_actual->m_num_children; i++)
	{
		if(parent_actual->m_children[i] == child)
		{
			parent_actual->m_num_children--;
			memmove(&parent_actual->m_children[i], &parent_actual->m_children[i+1], sizeof(*parent_actual->m_children)*(parent_actual->m_num_children-i));
			return;
		}
	}
	return;
}

size_t tree_node_get_num_children(struct tree_t *t, node_t n)
{
	if(t == NULL || n == INVALID_NODE || n>=t->m_num_nodes)
		return 0;
	return t->m_nodes[n].m_num_children;
}

node_t tree_node_get_child(struct tree_t *t, node_t n, size_t idx)
{
	if(t == NULL || n == INVALID_NODE || n>=t->m_num_nodes)
		return INVALID_NODE;
	if(idx >= t->m_nodes[n].m_num_children)
		return INVALID_NODE;
	return t->m_nodes[n].m_children[idx];
}

void *tree_node_get_data(struct tree_t *t, node_t n)
{
	if(t == NULL || n == INVALID_NODE || n>=t->m_num_nodes)
		return NULL;
	return t->m_nodes[n].m_data;
}

void tree_free(struct tree_t *t)
{
	for(size_t i=0; i<t->m_num_nodes; i++)
		free(t->m_nodes[i].m_children);
	free(t->m_nodes);
	free(t);
}

