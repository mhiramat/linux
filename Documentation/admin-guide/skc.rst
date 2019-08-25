.. SPDX-License-Identifier: GPL-2.0

================================
Supplemental Kernel Commandline
================================

:Author: Masami Hiramatsu <mhiramat@kernel.org>

Overview
========

Supplemental Kernel Commandline (SKC) is expanding current kernel cmdline
to support additional key-value data when boot the kernel in efficient way.
This allows adoministrators to pass a tree-structured key-value text file
(SKC file) via bootloaders.

SKC File Syntax
===============

SKC basic syntax is simple. Each key consists of dot-connected-words, and
key and value are connected by "=". The value has to be terminated by semi-
colon (";"). For array value, array entries are separated by comma (",").

KEY[.WORD[...]] = VALUE[, VALUE2[...]];

Each key word only contains alphabet, number, dash ("-") or underscore ("_").
If a value need to contain the delimiters, you can use double-quotes to
quote it. A double quote in VALUE can be escaped by backslash. There can
be a key which doesn't have value or has an empty value. Those keys are
used for checking the key exists or not (like a boolean).

Tree Structure
--------------

SKC allows user to merge partially same word keys by brace. For example,

foo.bar.baz = value1;
foo.bar.qux.quux = value2;

These can be written also in

foo.bar {
   baz = value1;
   qux.quux = value2;
}

In both style, same key words are automatically merged when parsing it
at boot time. So you can append similar trees or key-values.

SKC File Limitation
===================

Currently the maximum SKC file size is 32KB and the total key-words (not
key-value entries) must be under 512 nodes.

/proc/sup_cmdline
=================

/proc/sup_cmdline is the user-space interface of supplemental kernel
cmdline. Unlike /proc/cmdline, this file shows the key-value style list.
Each key-value pair is shown in each line with following style.

KEY[.WORDS...] = "[VALUE]"[,"VALUE2"...];

How to Pass at Boot
===================

SKC file is passed to kernel via memory, so the boot loader must support
loading SKC file. After loading the SKC file on memory, the boot loader
has to add "skc=PADDR,SIZE" argument to kernel cmdline, where the PADDR
is the physical address of the memory block and SIZE is the size of SKC
file.

SKC APIs
========

User can query or loop on key-value pairs, also it is possible to find
a root (prefix) key node and find key-values under that node.

If you have a key string, you can query the value directly with the key
using skc_find_value(). If you want to know what keys exist in the SKC
tree, you can use skc_for_each_key_value() to iterate key-value pairs.
Note that you need to use skc_array_for_each_value() for accessing
each arraies value, e.g.

::

 vnode = NULL;
 skc_find_value("key.word", &vnode);
 if (vnode && skc_node_is_array(vnode))
    skc_array_for_each_value(vnode, value) {
      printk("%s ", value);
    }

If you want to focus on keys which has a prefix string, you can use
skc_find_node() to find a node which prefix key words, and iterate
keys under the prefix node with skc_node_for_each_key_value().

But the most typical usage is to get the named value under prefix
or get the named array under prefix as below.

::

 root = skc_find_node("key.prefix");
 value = skc_node_find_value(root, "option", &vnode);
 ...
 skc_node_for_each_array_value(root, "array-option", value, anode) {
    ...
 }

This accesses a value of "key.prefix.option" and an array of
"key.prefix.array-option".

Locking is not needed, since after initialized, SKC becomes readonly.
All data and keys must be copied if you need to modify it.


Functions and structures
========================

.. kernel-doc:: include/linux/skc.h
.. kernel-doc:: lib/skc.c

