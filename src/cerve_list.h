/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Copyright (C) 2025 Carter Williams
 *
 * This file is part of Cerve.
 *
 * Cerve is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Cerve is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

/* This module will be contained in a single header file. The scope
 * of this module is simply to provide a mechanism for implementing linked
 * lists in C. This library was heavily inspired by the Linux kernel's linked
 * list implementation, and I wanted to provide a similar interface for my own
 * projects.
 *
 * The module will provide two types of linked lists: singly linked lists and
 * doubly linked lists. It may be simpler to provide only doubly linked lists,
 * but I did not want force the user to take on unnecessary overhead if they only
 * needed a singly linked list. Functions or macros that are denoted with an 's'
 * at the beginning of the name are for singly linked lists. Functions or macros
 * that are denoted with a 'd' at the beginning of the name are for doubly linked
 * lists. If neither of these prefixes are present, the function or macro is
 * intended to be used for both types of linked lists.
 *
 * Both types of linked lists will be circular. This means that the last node in
 * the list will point to the first node in the list. This is done because there
 * is almost no downside to having a circular list, but there can be many upsides.
 *
 * For a detailed explanation of the functions and macros, see the comments
 * in this file.
 */

#ifndef CERVE_SRC_LIST_H
#define CERVE_SRC_LIST_H

#include <stddef.h>

#include "cerve_cc.h"

#define container_of(ptr, type, member)                                      \
	((type *)cc_assume_aligned(((char *)(ptr) - offsetof(type, member)), \
				   cc_alignof(type)))

#define container_of_const(ptr, type, member)                   \
	((const type *)cc_assume_aligned(                       \
		((const char *)(ptr) - offsetof(type, member)), \
		cc_alignof(type)))

typedef struct slist_link slist_link;
typedef struct dlist_link dlist_link;

/* Singly linked list node. Add this as a member to your struct
 * that you'd like to form into a linked list.
 * Ex) Let's say I want to create a linked list of buffers. I'd
 * define my buffer struct like so:
 * struct buffer {
 *     char *b;
 *     size_t size;
 *     slist_link next;
 * };
 * Then I can chain these buffers together through the next member.
 */
struct slist_link {
	struct slist_link *next;
};

/* Doubly linked list node. Similar to the singly linked list node in every
 * aspect except it also points to a previous element. You should add
 * this to your structs in the exact same way as slist_link.
 */
struct dlist_link {
	struct dlist_link *next;
	struct dlist_link *prev;
};

/* Macro for getting the pointer to the struct that contains the
 * linked list node. The problem with intrusive linked lists it
 * that you never get a pointer to the containing struct (struct
 * buffer from the example above); you get a pointer to the linking
 * member. This macro calculates the memory address of the containing
 * struct and casts to it.
 *
 * @param ptr: The pointer to the slist_link or dlist_link node.
 * @param type: The type of the containing struct.
 * @param member: Name of the slist_link or dlist_link member in the
 * containing struct.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

/* Macro similar to list_entry, but preserves const-ness. */
#define list_entry_const(ptr, type, member) \
	container_of_const(ptr, type, member)

/* Macro for iterating through a linked list. This is a helper macro for
 * list_for_each and dlist_for_each_reverse. DO NOT USE THIS MACRO DIRECTLY.
 */
#define __list_for_each(head_ptr, entry_ptr, entry_type, entry_member,   \
			direction)                                       \
	for (entry_ptr = list_entry((head_ptr)->direction, entry_type,   \
				    entry_member);                       \
	     &((entry_ptr)->entry_member) != (head_ptr);                 \
	     entry_ptr = list_entry((entry_ptr)->entry_member.direction, \
				    entry_type, entry_member))

/* Macro for iterating through a linked list. This works with singly and doubly
 * linked lists. The macro will iterate through the list by following the next
 * pointer.
 *
 * @param head_ptr: Pointer to the head of the list.
 * @param entry_ptr: Pointer to a variable of type entry_type. This variable
 * will point to the current containing struct.
 * @param entry_type: The type of the containing struct.
 * @param entry_member: Name of the linking member in entry_type. This
 * should be of type slist_link or dlist_link.
 * @example: list_for_each(&buf_head, buf_ptr, struct buffer, next) { ... }
 */
#define list_for_each(head_ptr, entry_ptr, entry_type, entry_member) \
	__list_for_each(head_ptr, entry_ptr, entry_type, entry_member, next)

/* Macro for iterating through a linked list in reverse. This only works with
 * doubly linked lists. Exactly the same as list_for_each, but follows the prev
 * pointer. See list_for_each for more information.
 */
#define dlist_for_each_reverse(head_ptr, entry_ptr, entry_type, entry_member) \
	__list_for_each(head_ptr, entry_ptr, entry_type, entry_member, prev)

/* Returns a non-zero value if there are no other nodes in the list.
 *
 * @param ptr: The head of the list.
 */
#define list_empty(ptr) ((ptr)->next == (ptr))

/* This is a helper function used to find the previous node in a singly linked list.
 * It is used by the slist_del, slist_add_tail, and slist_splice functions. It takes
 * O(n) time to find the previous node. If this is called frequently, consider using
 * a doubly linked list.
 *
 * @param head: The head of the list.
 * @param prev: A pointer to a pointer that will hold the previous node. The previous
 * pointer is placed in this variable.
 */
static void slist_find_prev(slist_link *head, slist_link **prev)
{
	slist_link *next = head->next;
	*prev = head;
	while (next != head) {
		*prev = next;
		next = next->next;
	}
}

/* Initialize a singly linked list to be empty. Allows for initialization after
 * compile time.
 *
 * @param head: The head of the list.
 */
static void slist_init(slist_link *head)
{
	head->next = head;
}

/* Adds a node directly after the passed in head of the list. It takes O(1)
 * time to add a node to the list.
 *
 * @param new: The node to add to the list.
 * @param head: The head of the list.
 */
static void slist_add(slist_link *new, slist_link *head)
{
	slist_link *next = head->next;
	head->next = new;
	new->next = next;
}

/* Adds a node to the end of the list. This takes O(n) time to add a node to the
 * list because slist_find_prev is called.
 *
 * @param new: The node to add to the list.
 * @param head: The head of the list.
 */
static void slist_add_tail(slist_link *new, slist_link *head)
{
	slist_link *prev;
	slist_find_prev(head, &prev);
	prev->next = new;
	new->next = head;
}

/* Deletes a node from the list. This takes O(n) time to delete a node from the list
 * because slist_find_prev is called.
 *
 * @param node: The node to delete from the list.
 * @aparam head: Head of the list.
 */
static void slist_del(slist_link *node, slist_link *head)
{
	slist_link *prev = head;

	while (prev->next != head) {
		if (prev->next == node) {
			prev->next = node->next;
			return;
		}
		prev = prev->next;
	}
}

/* Splices a list into another list. This takes O(n) time to splice the list into
 * the other list because slist_find_prev is called. Similarly to slist_add, this
 * function adds the list directly after the head.
 *
 * @param list: The list to splice into the head of the other list.
 * @param head: The head of the list to splice into.
 */
static void slist_splice(slist_link *list, slist_link *head)
{
	slist_link *list_tail;
	slist_link *head_next;
	slist_find_prev(list, &list_tail);

	head_next = head->next;
	head->next = list;
	list_tail->next = head_next;
}

/* Initialize a doubly linked list to be empty. Allows for initialization after
 * compile time.
 *
 * @param head: The head of the list.
 */
static void dlist_init(dlist_link *head)
{
	head->next = head;
	head->prev = head;
}

/* Adds a node directly after the passed in head of the list. This function
 * can be used to build a stack by adding nodes and deleting head.next.
 *
 * @param new: The node to add to the list.
 * @param head: The head of the list.
 */
static void dlist_add(dlist_link *new, dlist_link *head)
{
	dlist_link *next = head->next;
	/* Fix old */
	next->prev = new;
	head->next = new;
	/* Make new */
	new->next = next;
	new->prev = head;
}

/* Adds a node to the end of the list. Unlike slist_add_tail, this function takes
 * O(1) time to add a node to the list. This function can be used to build a queue
 * by adding nodes to the tail and deleting head.next.
 *
 * @param new: The node to add to the list.
 * @param head: The head of the list.
 */
static void dlist_add_tail(dlist_link *new, dlist_link *head)
{
	dlist_add(new, head->prev);
}

/* Deletes a node from the list. This takes O(1) time to delete a node from the list
 * unlike slist_del.
 *
 * @param node: The node to delete from the list.
 */
static void dlist_del(dlist_link *node)
{
	dlist_link *prev = node->prev;
	prev->next = node->next;
	node->next->prev = prev;
}

/* Splices a list into another list. This takes O(1) time. Similarly to
 * dlist_add, this function adds the list directly after the head.
 *
 * @param list: The list to splice into the head of the other list.
 * @param head: The head of the list to splice into.
 */
static void dlist_splice(dlist_link *list, dlist_link *head)
{
	dlist_link *list_tail = list->prev;
	dlist_link *head_next = head->next;
	head->next = list;
	list->prev = head;

	list_tail->next = head_next;
	head_next->prev = list_tail;
}

#endif /* CERVE_SRC_LIST_H */
