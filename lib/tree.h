#ifndef H_TREE
#define H_TREE

#include <stddef.h>
#include <string.h>

#define INVALID_NODE ((size_t)-1)


struct tree_t;
typedef size_t node_t;

struct tree_t *tree_create(void);
node_t tree_get_root(struct tree_t *t);
node_t tree_node_create(struct tree_t *t);
void tree_node_free(struct tree_t *t, node_t);
void tree_node_set_data(struct tree_t *t, node_t, void *);
void tree_node_set_parent(struct tree_t *t, node_t child, node_t parent);
void tree_node_unlink_child(struct tree_t *t, node_t child);
size_t tree_node_get_num_children(struct tree_t *t, node_t n);
node_t tree_node_get_child(struct tree_t *t, node_t n, size_t idx);
node_t tree_node_get_parent(struct tree_t *t, node_t n);
void *tree_node_get_data(struct tree_t *t, node_t n);
void tree_free(struct tree_t *t);

#endif
