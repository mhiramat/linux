// SPDX-License-Identifier: GPL-2.0
/*
 * Supplemental Kernel Commandline
 * Masami Hiramatsu <mhiramat@kernel.org>
 */

#define pr_fmt(fmt)    "skc: " fmt

#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/skc.h>
#include <linux/string.h>

/*
 * Supplemental Kernel Commandline (SKC) is given as tree-structured ascii
 * text of key-value pairs on memory.
 * skc_parse() parses the text to build a simple tree. Each tree node is
 * simply a key word or a value. A key node may have a next key node or/and
 * a child node (both key and value). A value node may have a next value
 * node (for array).
 */

static struct skc_node skc_nodes[SKC_NODE_MAX] __initdata;
static int skc_node_num __initdata;
static char *skc_data __initdata;
static size_t skc_data_size __initdata;
static struct skc_node *last_parent __initdata;

static int __init skc_parse_error(const char *msg, const char *p)
{
	int line = 0, col = 0;
	int i, pos = p - skc_data;

	for (i = 0; i < pos; i++) {
		if (skc_data[i] == '\n') {
			line++;
			col = pos - i;
		}
	}
	pr_err("Parse error at line %d, col %d: %s\n", line + 1, col + 1, msg);
	return -EINVAL;
}

/**
 * skc_root_node() - Get the root node of supplemental kernel cmdline
 *
 * Return the address of root node of supplemental kernel cmdline. If the
 * supplemental kernel cmdline is not initiized, return NULL.
 */
struct skc_node * __init skc_root_node(void)
{
	if (unlikely(!skc_data))
		return NULL;

	return skc_nodes;
}

/**
 * skc_node_index() - Get the index of SKC node
 * @node: A target node of getting index.
 *
 * Return the index number of @node in SKC node list.
 */
int __init skc_node_index(struct skc_node *node)
{
	return node - &skc_nodes[0];
}

/**
 * skc_node_get_parent() - Get the parent SKC node
 * @node: An SKC node.
 *
 * Return the parent node of @node. If the node is top node of the tree,
 * return NULL.
 */
struct skc_node * __init skc_node_get_parent(struct skc_node *node)
{
	return node->parent == SKC_NODE_MAX ? NULL : &skc_nodes[node->parent];
}

/**
 * skc_node_get_child() - Get the child SKC node
 * @node: An SKC node.
 *
 * Return the first child node of @node. If the node has no child, return
 * NULL.
 */
struct skc_node * __init skc_node_get_child(struct skc_node *node)
{
	return node->child ? &skc_nodes[node->child] : NULL;
}

/**
 * skc_node_get_next() - Get the next sibling SKC node
 * @node: An SKC node.
 *
 * Return the NEXT sibling node of @node. If the node has no next sibling,
 * return NULL. Note that even if this returns NULL, it doesn't mean @node
 * has no siblings. (You also has to check whether the parent's child node
 * is @node or not.)
 */
struct skc_node * __init skc_node_get_next(struct skc_node *node)
{
	return node->next ? &skc_nodes[node->next] : NULL;
}

/**
 * skc_node_get_data() - Get the data of SKC node
 * @node: An SKC node.
 *
 * Return the data (which is always a null terminated string) of @node.
 * If the node has invalid data, warn and return NULL.
 */
const char * __init skc_node_get_data(struct skc_node *node)
{
	int offset = node->data & ~SKC_VALUE;

	if (WARN_ON(offset >= skc_data_size))
		return NULL;

	return skc_data + offset;
}

static bool __init
skc_node_match_prefix(struct skc_node *node, const char **prefix)
{
	const char *p = skc_node_get_data(node);
	int len = strlen(p);

	if (strncmp(*prefix, p, len))
		return false;

	p = *prefix + len;
	if (*p == '.')
		p++;
	else if (*p != '\0')
		return false;
	*prefix = p;

	return true;
}

/**
 * skc_node_find_child() - Find a child node which matches given key
 * @parent: An SKC node.
 * @key: A key string.
 *
 * Search a node under @parent which matches @key. The @key can contain
 * several words jointed with '.'. If @parent is NULL, this searches the
 * node from whole tree. Return NULL if no node is matched.
 */
struct skc_node * __init
skc_node_find_child(struct skc_node *parent, const char *key)
{
	struct skc_node *node;

	if (parent)
		node = skc_node_get_child(parent);
	else
		node = skc_root_node();

	while (node && skc_node_is_key(node)) {
		if (!skc_node_match_prefix(node, &key))
			node = skc_node_get_next(node);
		else if (*key != '\0')
			node = skc_node_get_child(node);
		else
			break;
	}

	return node;
}

/**
 * skc_node_find_value() - Find a value node which matches given key
 * @parent: An SKC node.
 * @key: A key string.
 * @vnode: A container pointer of found SKC node.
 *
 * Search a value node under @parent whose (parent) key node matches @key,
 * store it in *@vnode, and returns the value string.
 * The @key can contain several words jointed with '.'. If @parent is NULL,
 * this searches the node from whole tree. Return the value string if a
 * matched key found, return NULL if no node is matched.
 * Note that this returns 0-length string and stores NULL in *@vnode if the
 * key has no value. And also it will return the value of the first entry if
 * the value is an array.
 */
const char * __init
skc_node_find_value(struct skc_node *parent, const char *key,
		    struct skc_node **vnode)
{
	struct skc_node *node = skc_node_find_child(parent, key);

	if (!node || !skc_node_is_key(node))
		return NULL;

	node = skc_node_get_child(node);
	if (node && !skc_node_is_value(node))
		return NULL;

	if (vnode)
		*vnode = node;

	return node ? skc_node_get_data(node) : "";
}

/**
 * skc_node_compose_key() - Compose key string of the SKC node
 * @node: An SKC node.
 * @buf: A buffer to store the key.
 * @size: The size of the @buf.
 *
 * Compose the full-length key of the @node into @buf. Returns the total
 * length of the key stored in @buf. Or returns -EINVAL if @node is NULL,
 * and -ERANGE if the key depth is deeper than max depth.
 */
int __init skc_node_compose_key(struct skc_node *node, char *buf, size_t size)
{
	u16 keys[SKC_DEPTH_MAX];
	int depth = 0, ret = 0, total = 0;

	if (!node)
		return -EINVAL;

	if (skc_node_is_value(node))
		node = skc_node_get_parent(node);

	while (node) {
		keys[depth++] = skc_node_index(node);
		if (depth == SKC_DEPTH_MAX)
			return -ERANGE;
		node = skc_node_get_parent(node);
	}

	while (--depth >= 0) {
		node = skc_nodes + keys[depth];
		ret = snprintf(buf, size, "%s%s", skc_node_get_data(node),
			       depth ? "." : "");
		if (ret < 0)
			return ret;
		if (ret > size) {
			size = 0;
		} else {
			size -= ret;
			buf += ret;
		}
		total += ret;
	}

	return total;
}

/**
 * skc_node_find_next_leaf() - Find the next leaf node under given node
 * @root: An SKC root node
 * @node: An SKC node which starts from.
 *
 * Search the next leaf node (which means the terminal key node) of @node
 * under @root node (including @root node itself).
 * Return the next node or NULL if next leaf node is not found.
 */
struct skc_node * __init skc_node_find_next_leaf(struct skc_node *root,
						 struct skc_node *node)
{
	if (unlikely(!skc_data))
		return NULL;

	if (!node) {	/* First try */
		node = root;
		if (!node)
			node = skc_nodes;
	} else {
		if (node == root)	/* @root was a leaf, no child node. */
			return NULL;

		while (!node->next) {
			node = skc_node_get_parent(node);
			if (node == root)
				return NULL;
			/* User passed a node which is not uder parent */
			if (WARN_ON(!node))
				return NULL;
		}
		node = skc_node_get_next(node);
	}

	while (node && !skc_node_is_leaf(node))
		node = skc_node_get_child(node);

	return node;
}

/**
 * skc_node_find_next_key_value() - Find the next key-value pair nodes
 * @root: An SKC root node
 * @leaf: A container pointer of SKC node which starts from.
 *
 * Search the next leaf node (which means the terminal key node) of *@leaf
 * under @root node. Returns the value and update *@leaf if next leaf node
 * is found, or NULL if no next leaf node is found.
 * Note that this returns 0-length string if the key has no value, or
 * the value of the first entry if the value is an array.
 */
const char * __init skc_node_find_next_key_value(struct skc_node *root,
						 struct skc_node **leaf)
{
	/* tip must be passed */
	if (WARN_ON(!leaf))
		return NULL;

	*leaf = skc_node_find_next_leaf(root, *leaf);
	if (!*leaf)
		return NULL;
	if ((*leaf)->child)
		return skc_node_get_data(skc_node_get_child(*leaf));
	else
		return "";	/* No value key */
}

/* SKC parse and tree build */

static struct skc_node * __init skc_add_node(char *data, u32 flag)
{
	struct skc_node *node;
	unsigned long offset;

	if (skc_node_num == SKC_NODE_MAX)
		return NULL;

	node = &skc_nodes[skc_node_num++];
	offset = data - skc_data;
	node->data = (u16)offset;
	if (WARN_ON(offset >= SKC_DATA_MAX))
		return NULL;
	node->data |= flag;
	node->child = 0;
	node->next = 0;

	return node;
}

static inline __init struct skc_node *skc_last_sibling(struct skc_node *node)
{
	while (node->next)
		node = skc_node_get_next(node);

	return node;
}

static struct skc_node * __init skc_add_sibling(char *data, u32 flag)
{
	struct skc_node *sib, *node = skc_add_node(data, flag);

	if (node) {
		if (!last_parent) {
			node->parent = SKC_NODE_MAX;
			sib = skc_last_sibling(skc_nodes);
			sib->next = skc_node_index(node);
		} else {
			node->parent = skc_node_index(last_parent);
			if (!last_parent->child) {
				last_parent->child = skc_node_index(node);
			} else {
				sib = skc_node_get_child(last_parent);
				sib = skc_last_sibling(sib);
				sib->next = skc_node_index(node);
			}
		}
	}

	return node;
}

static inline __init struct skc_node *skc_add_child(char *data, u32 flag)
{
	struct skc_node *node = skc_add_sibling(data, flag);

	if (node)
		last_parent = node;

	return node;
}

static inline __init bool skc_valid_keyword(char *key)
{
	if (key[0] == '\0')
		return false;

	while (isalnum(*key) || *key == '-' || *key == '_')
		key++;

	return *key == '\0';
}

static inline __init char *find_ending_quote(char *p)
{
	do {
		p = strchr(p + 1, '"');
		if (!p)
			break;
	} while (*(p - 1) == '\\');

	return p;
}

/* Return delimiter or error, no node added */
static int __init __skc_parse_value(char **__v, char **__n)
{
	char *p, *v = *__v;
	int c;

	v = skip_spaces(v);
	if (*v == '"') {
		v++;
		p = find_ending_quote(v);
		if (!p)
			return skc_parse_error("No closing quotation", v);
		*p++ = '\0';
		p = skip_spaces(p);
		if (*p != ',' && *p != ';')
			return skc_parse_error("No delimiter for value", v);
		c = *p;
		*p++ = '\0';
	} else {
		p = strpbrk(v, ",;");
		if (!p)
			return skc_parse_error("No delimiter for value", v);
		c = *p;
		*p++ = '\0';
		v = strim(v);
	}
	*__v = v;
	*__n = p;

	return c;
}

static int __init skc_parse_array(char **__v)
{
	struct skc_node *node;
	char *next;
	int c = 0;

	do {
		c = __skc_parse_value(__v, &next);
		if (c < 0)
			return c;

		node = skc_add_sibling(*__v, SKC_VALUE);
		if (!node)
			return -ENOMEM;
		*__v = next;
	} while (c != ';');
	node->next = 0;

	return 0;
}

static inline __init
struct skc_node *find_match_node(struct skc_node *node, char *k)
{
	while (node) {
		if (!strcmp(skc_node_get_data(node), k))
			break;
		node = skc_node_get_next(node);
	}
	return node;
}

static int __init __skc_add_key(char *k)
{
	struct skc_node *node;

	if (!skc_valid_keyword(k))
		return skc_parse_error("Invalid keyword", k);

	if (unlikely(skc_node_num == 0))
		goto add_node;

	if (!last_parent)	/* the first level */
		node = find_match_node(skc_nodes, k);
	else
		node = find_match_node(skc_node_get_child(last_parent), k);

	if (node)
		last_parent = node;
	else {
add_node:
		node = skc_add_child(k, SKC_KEY);
		if (!node)
			return -ENOMEM;
	}
	return 0;
}

static int __init __skc_parse_keys(char *k)
{
	char *p;
	int ret;

	k = strim(k);
	while ((p = strchr(k, '.'))) {
		*p++ = '\0';
		ret = __skc_add_key(k);
		if (ret)
			return ret;
		k = p;
	}

	return __skc_add_key(k);
}

static int __init skc_parse_kv(char **k, char *v)
{
	struct skc_node *prev_parent = last_parent;
	struct skc_node *node;
	char *next;
	int c, ret;

	ret = __skc_parse_keys(*k);
	if (ret)
		return ret;

	c = __skc_parse_value(&v, &next);
	if (c < 0)
		return c;

	node = skc_add_sibling(v, SKC_VALUE);
	if (!node)
		return -ENOMEM;

	if (c == ',') {	/* Array */
		ret = skc_parse_array(&next);
		if (ret < 0)
			return ret;
	}

	last_parent = prev_parent;

	*k = next;

	return 0;
}

static int __init skc_parse_key(char **k, char *n)
{
	struct skc_node *prev_parent = last_parent;
	int ret;

	*k = strim(*k);
	if (**k != '\0') {
		ret = __skc_parse_keys(*k);
		if (ret)
			return ret;
		last_parent = prev_parent;
	}

	*k = n;

	return 0;
}

static int __init skc_open_brace(char **k, char *n)
{
	int ret;

	ret = __skc_parse_keys(*k);
	if (ret)
		return ret;

	/* Mark the last key as open brace */
	last_parent->next = SKC_NODE_MAX;

	*k = n;

	return 0;
}

static int __init skc_close_brace(char **k, char *n)
{
	struct skc_node *node;

	*k = strim(*k);
	if (**k != '\0')
		return skc_parse_error("Unexpected key, maybe forgot ;?", *k);

	if (!last_parent || last_parent->next != SKC_NODE_MAX)
		return skc_parse_error("Unexpected closing brace", *k);

	node = last_parent;
	node->next = 0;
	do {
		node = skc_node_get_parent(node);
	} while (node && node->next != SKC_NODE_MAX);
	last_parent = node;

	*k = n;

	return 0;
}

static int __init skc_verify_tree(void)
{
	int i;

	for (i = 0; i < skc_node_num; i++) {
		if (skc_nodes[i].next > skc_node_num) {
			return skc_parse_error("No closing brace",
				skc_node_get_data(skc_nodes + i));
		}
	}

	return 0;
}

/**
 * skc_init() - Parse given SKC file and build SKC internal tree
 * @buf: Supplemental kernel cmdline text
 *
 * This parses the supplemental kernel cmdline text in @buf. @buf must be a
 * null terminated string and smaller than SKC_DATA_MAX.
 * Return 0 if succeeded, or -errno if there is any error.
 */
int __init skc_init(char *buf)
{
	char *p, *q;
	int ret, c;

	if (skc_data)
		return -EBUSY;

	ret = strlen(buf);
	if (ret > SKC_DATA_MAX - 1 || ret == 0)
		return -ERANGE;

	skc_data = buf;
	skc_data_size = ret + 1;

	p = buf;
	do {
		q = strpbrk(p, "{}=;");
		if (!q)
			break;
		c = *q;
		*q++ = '\0';
		switch (c) {
		case '=':
			ret = skc_parse_kv(&p, q);
			break;
		case '{':
			ret = skc_open_brace(&p, q);
			break;
		case ';':
			ret = skc_parse_key(&p, q);
			break;
		case '}':
			ret = skc_close_brace(&p, q);
			break;
		}
	} while (ret == 0);

	if (ret < 0)
		return ret;

	if (!q) {
		p = skip_spaces(p);
		if (*p != '\0')
			return skc_parse_error("No delimiter", p);
	}

	return skc_verify_tree();
}

/**
 * skc_debug_dump() - Dump current SKC node list
 *
 * Dump the current SKC node list on printk buffer for debug.
 */
void __init skc_debug_dump(void)
{
	int i;

	for (i = 0; i < skc_node_num; i++) {
		pr_debug("[%d] %s (%s) .next=%d, .child=%d .parent=%d\n", i,
			skc_node_get_data(skc_nodes + i),
			skc_node_is_value(skc_nodes + i) ? "value" : "key",
			skc_nodes[i].next, skc_nodes[i].child,
			skc_nodes[i].parent);
	}
}
