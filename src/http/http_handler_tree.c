#include "http_handler_tree.h"
#include "../common.h"
#include <stdlib.h>
#define RAWHTTP_HANDLER_TREE_INVALID_NEXT -1
#define RAWHTTP_HANDLER_TREE_INVALID_CHILD -1

int rawhttp_handler_tree_create(rawhttp_handler_tree* tree, long long capacity)
{
	tree->elements = calloc(capacity, sizeof(rawhttp_handler_tree_element));
	if (!tree->elements) return -1;
	tree->num_elements = 1;
	tree->capacity = capacity;
	tree->elements[0].has_handler = false;
	tree->elements[0].child = RAWHTTP_HANDLER_TREE_INVALID_CHILD;
	tree->elements[0].next = RAWHTTP_HANDLER_TREE_INVALID_NEXT;
	tree->elements[0].valid = true;
	tree->elements[0].pattern = "/";
	tree->elements[0].pattern_size = 1;
	return 0;
}

void rawhttp_handler_tree_destroy(rawhttp_handler_tree* tree)
{
	free(tree->elements);
}

static long long rawhttp_handler_tree_pattern_get_levels(const char* pattern, long long pattern_size, int is_subtree_root)
{
	long long levels = 0, pos = 0;
	while (pos < pattern_size)
		if (pattern[pos++] == '/')
			++levels;
	if (!is_subtree_root) ++levels;
	return levels;
}

static long long rawhttp_handler_tree_pattern_get_size_of_level(const char* pattern, long long pattern_size, long long level)
{
	long long size = 0;

	while (level >= 0 && size != pattern_size)
	{
		if (pattern[size] == '/')
		{
			if (level == 0)
			    return ++size;

			--level;
		}
		++size;
	}
	
	return pattern_size;
}

static int rawhttp_handler_tree_grow(rawhttp_handler_tree* tree, long long new_capacity)
{
	tree->elements = realloc(tree->elements, new_capacity * sizeof(rawhttp_handler_tree_element));
	if (tree->elements == NULL) return -1;
	tree->capacity = new_capacity;
	return 0;
}

static int rawhttp_handler_tree_create_element(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size, long long pattern_level, long long pattern_total_levels,
	long long* created_element_root, const rawhttp_server_handler* handler, int is_subtree_root)
{
	rawhttp_handler_tree_element* new_element = NULL;
	rawhttp_handler_tree_element* previous_element = NULL;
	long long new_pattern_split_size;
	*created_element_root = tree->num_elements;

	do
	{
		// Grow tree if necessary
		if (tree->num_elements == tree->capacity)
			if (rawhttp_handler_tree_grow(tree, 2 * tree->capacity))
				return -1;

		new_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(pattern, pattern_size, pattern_level);
		new_element = &tree->elements[tree->num_elements++];
		new_element->child = RAWHTTP_HANDLER_TREE_INVALID_CHILD;
		new_element->has_handler = false;
		new_element->next = RAWHTTP_HANDLER_TREE_INVALID_NEXT;
		new_element->pattern = pattern;
		new_element->pattern_size = new_pattern_split_size;
		new_element->subtree_root = true;
		new_element->valid = true;
		if (previous_element) previous_element->child = tree->num_elements - 1;
		previous_element = new_element;
		++pattern_level;
	}
	while (pattern_level < pattern_total_levels);

	previous_element->subtree_root = is_subtree_root;
	previous_element->handler = *handler;
	previous_element->has_handler = true;
	return 0;
}

static int rawhttp_handler_tree_is_pattern_subtree_root(const char* pattern, long long pattern_size)
{
	return pattern[pattern_size - 1] == '/';
}

int rawhttp_handler_tree_put(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size, rawhttp_server_handle_func handle)
{
	rawhttp_server_handler handler;
	handler.handle = handle;

	long long pattern_total_levels, pattern_level = 0;
	long long new_pattern_split_size, current_pattern_split_size;
	rawhttp_handler_tree_element* current_element = &tree->elements[0];
	long long created_element_index;
	int is_subtree_root = rawhttp_handler_tree_is_pattern_subtree_root(pattern, pattern_size);

	pattern_total_levels = rawhttp_handler_tree_pattern_get_levels(pattern, pattern_size, is_subtree_root);

	while (true)
	{
		current_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(current_element->pattern, current_element->pattern_size, pattern_level);
		new_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(pattern, pattern_size, pattern_level);
		
		if (new_pattern_split_size == current_pattern_split_size && !strncmp(pattern, current_element->pattern, new_pattern_split_size))
		{
			// Pattern split match!
			if (pattern_level == pattern_total_levels - 1)
			{
				if (current_element->has_handler)
					return -1;
				else
				{
					current_element->has_handler = true;
					current_element->handler = handler;
					return 0;
				}
			}
			else if (current_element->child == RAWHTTP_HANDLER_TREE_INVALID_CHILD)
			{
				if (rawhttp_handler_tree_create_element(tree, pattern, pattern_size, pattern_level + 1, pattern_total_levels,
					&created_element_index, &handler, is_subtree_root))
					return -1;
				current_element->child = created_element_index;
				return 0;
			}
			else
			{
				++pattern_level;
				current_element = &tree->elements[current_element->child];
			}
		}
		else
		{
			// Different pattern split
			if (current_element->next == RAWHTTP_HANDLER_TREE_INVALID_NEXT)
			{
				if (rawhttp_handler_tree_create_element(tree, pattern, pattern_size, pattern_level, pattern_total_levels,
					&created_element_index, &handler, is_subtree_root))
					return -1;
				current_element->next = created_element_index;
				return 0;
			}
			else
				current_element = &tree->elements[current_element->next];
		}
	}
}

const rawhttp_server_handler* rawhttp_handler_tree_get(rawhttp_handler_tree* tree, const char* pattern, long long pattern_size)
{
	long long pattern_total_levels, pattern_level = 0;
	long long new_pattern_split_size, current_pattern_split_size;
	rawhttp_handler_tree_element* current_element = &tree->elements[0];
	int is_subtree_root = rawhttp_handler_tree_is_pattern_subtree_root(pattern, pattern_size);
	rawhttp_server_handler* handler = NULL;

	pattern_total_levels = rawhttp_handler_tree_pattern_get_levels(pattern, pattern_size, is_subtree_root);

	while (true)
	{
		current_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(current_element->pattern, current_element->pattern_size, pattern_level);
		new_pattern_split_size = rawhttp_handler_tree_pattern_get_size_of_level(pattern, pattern_size, pattern_level);
		
		if (new_pattern_split_size == current_pattern_split_size && !strncmp(pattern, current_element->pattern, new_pattern_split_size))
		{
			if (current_element->has_handler)
				handler = &current_element->handler;

			// Pattern split match!
			if (pattern_level == pattern_total_levels - 1 || current_element->child == RAWHTTP_HANDLER_TREE_INVALID_CHILD)
				break;
			else
			{
				++pattern_level;
				current_element = &tree->elements[current_element->child];
			}
		}
		else
		{
			// Different pattern split
			if (current_element->next == RAWHTTP_HANDLER_TREE_INVALID_NEXT)
				break;
			else
				current_element = &tree->elements[current_element->next];
		}
	}

	return handler;
}