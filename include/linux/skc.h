/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SKC_H
#define _LINUX_SKC_H
/*
 * Supplemental Kernel Command Line
 * Copyright (C) 2019 Linaro Ltd.
 * Author: Masami Hiramatsu <mhiramat@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/types.h>

/* SKC tree node */
struct skc_node {
	u16 next;
	u16 child;
	u16 parent;
	u16 data;
} __attribute__ ((__packed__));

#define SKC_KEY		0
#define SKC_VALUE	(1 << 15)
/* Maximum size of supplemental kernel cmdline is 32KB - 1 */
#define SKC_DATA_MAX	(SKC_VALUE - 1)

#define SKC_NODE_MAX	512
#define SKC_KEYLEN_MAX	256
#define SKC_DEPTH_MAX	16

/* Node tree access raw APIs */
struct skc_node * __init skc_root_node(void);
int __init skc_node_index(struct skc_node *node);
struct skc_node * __init skc_node_get_parent(struct skc_node *node);
struct skc_node * __init skc_node_get_child(struct skc_node *node);
struct skc_node * __init skc_node_get_next(struct skc_node *node);
const char * __init skc_node_get_data(struct skc_node *node);

/**
 * skc_node_is_value() - Test the node is a value node
 * @node: An SKC node.
 *
 * Test the @node is a value node and return true if a value node, false if not.
 */
static inline __init bool skc_node_is_value(struct skc_node *node)
{
	return !!(node->data & SKC_VALUE);
}

/**
 * skc_node_is_key() - Test the node is a key node
 * @node: An SKC node.
 *
 * Test the @node is a key node and return true if a key node, false if not.
 */
static inline __init bool skc_node_is_key(struct skc_node *node)
{
	return !(node->data & SKC_VALUE);
}

/**
 * skc_node_is_array() - Test the node is an arraied value node
 * @node: An SKC node.
 *
 * Test the @node is an arraied value node.
 */
static inline __init bool skc_node_is_array(struct skc_node *node)
{
	return skc_node_is_value(node) && node->next != 0;
}

/**
 * skc_node_is_leaf() - Test the node is a leaf key node
 * @node: An SKC node.
 *
 * Test the @node is a leaf key node which is a key node and has a value node
 * or no child. Returns true if it is a leaf node, or false if not.
 */
static inline __init bool skc_node_is_leaf(struct skc_node *node)
{
	return skc_node_is_key(node) &&
		(!node->child || skc_node_is_value(skc_node_get_child(node)));
}

/* Tree-based key-value access APIs */
struct skc_node * __init skc_node_find_child(struct skc_node *parent,
					     const char *key);

const char * __init skc_node_find_value(struct skc_node *parent,
					const char *key,
					struct skc_node **vnode);

struct skc_node * __init skc_node_find_next_leaf(struct skc_node *root,
						 struct skc_node *leaf);

const char * __init skc_node_find_next_key_value(struct skc_node *root,
						 struct skc_node **leaf);

/**
 * skc_find_value() - Find a value which matches the key
 * @key: Search key
 * @vnode: A container pointer of SKC value node.
 *
 * Search a value whose key matches @key from whole of SKC tree and return
 * the value if found. Found value node is stored in *@vnode.
 * Note that this can return 0-length string and store NULL in *@vnode for
 * key-only (non-value) entry.
 */
static inline const char * __init
skc_find_value(const char *key, struct skc_node **vnode)
{
	return skc_node_find_value(NULL, key, vnode);
}

/**
 * skc_find_node() - Find a node which matches the key
 * @key: Search key
 * @value: A container pointer of SKC value node.
 *
 * Search a (key) node whose key matches @key from whole of SKC tree and
 * return the node if found. If not found, returns NULL.
 */
static inline struct skc_node * __init skc_find_node(const char *key)
{
	return skc_node_find_child(NULL, key);
}

/**
 * skc_array_for_each_value() - Iterate value nodes on an array
 * @anode: An SKC arraied value node
 * @value: A value
 *
 * Iterate array value nodes and values starts from @anode. This is expected to
 * be used with skc_find_value() and skc_node_find_value(), so that user can
 * process each array entry node.
 */
#define skc_array_for_each_value(anode, value)				\
	for (value = skc_node_get_data(anode); anode != NULL ;		\
	     anode = skc_node_get_next(anode),				\
	     value = anode ? skc_node_get_data(anode) : NULL)

/**
 * skc_node_for_each_child() - Iterate child nodes
 * @parent: An SKC node.
 * @child: Iterated SKC node.
 *
 * Iterate child nodes of @parent. Each child nodes are stored to @child.
 */
#define skc_node_for_each_child(parent, child)				\
	for (child = skc_node_get_child(parent); child != NULL ;	\
	     child = skc_node_get_next(child))

/**
 * skc_node_for_each_array_value() - Iterate array entries of geven key
 * @node: An SKC node.
 * @key: A key string searched under @node
 * @anode: Iterated SKC node of array entry.
 * @value: Iterated value of array entry.
 *
 * Iterate array entries of given @key under @node. Each array entry node
 * is stroed to @anode and @value. If the @node doesn't have @key node,
 * it does nothing.
 * Note that even if the found key node has only one value (not array)
 * this executes block once. Hoever, if the found key node has no value
 * (key-only node), this does nothing. So don't use this for testing the
 * key-value pair existence.
 */
#define skc_node_for_each_array_value(node, key, anode, value)		\
	for (value = skc_node_find_value(node, key, &anode); value != NULL; \
	     anode = skc_node_get_next(anode),				\
	     value = anode ? skc_node_get_data(anode) : NULL)

/**
 * skc_node_for_each_key_value() - Iterate key-value pairs under a node
 * @node: An SKC node.
 * @knode: Iterated key node
 * @value: Iterated value string
 *
 * Iterate key-value pairs under @node. Each key node and value string are
 * stored in @knode and @value respectively.
 */
#define skc_node_for_each_key_value(node, knode, value)			\
	for (knode = NULL, value = skc_node_find_next_key_value(node, &knode);\
	     knode != NULL; value = skc_node_find_next_key_value(node, &knode))

/**
 * skc_for_each_key_value() - Iterate key-value pairs
 * @knode: Iterated key node
 * @value: Iterated value string
 *
 * Iterate key-value pairs in whole SKC tree. Each key node and value string
 * are stored in @knode and @value respectively.
 */
#define skc_for_each_key_value(knode, value)				\
	skc_node_for_each_key_value(NULL, knode, value)

/* Compose complete key */
int __init skc_node_compose_key(struct skc_node *node, char *buf, size_t size);

/* SKC node initializer */
int __init skc_init(char *buf);

/* Debug dump functions */
void __init skc_debug_dump(void);

#endif
