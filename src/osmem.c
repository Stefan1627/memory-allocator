// SPDX-License-Identifier: BSD-3-Clause
#include <stdint.h>
#include <sys/mman.h>
#include "../tests/snippets/test-utils.h"

#define PAGE_SIZE (4096)
#define ALIGNMENT 8
#define ALIGN(size) (((size) % ALIGNMENT == 0) ? (size) : ((size) + (ALIGNMENT - (size) % 8)))

struct block_meta *head, *last;

// if type  is 0, it's a alloc block
// if type is 1, it's a mapped block
int type;
int coming_from_calloc;

struct block_meta *get_block_ptr(void *ptr);
struct block_meta *get_last(struct block_meta *head);
struct block_meta *get_head(struct block_meta *block);
void expand_block(struct block_meta *block, size_t size, size_t current_size);
void coalescing_list(struct block_meta **block);
void split_block(struct block_meta *block, size_t size);
struct block_meta *find_best(size_t size);
struct block_meta *request_space(struct block_meta *last, size_t size);
void coalesce_all(void);


void *os_malloc(size_t size)
{
	size_t page_size = MMAP_THRESHOLD;

	if (coming_from_calloc == 1) {
		page_size = getpagesize();
		coming_from_calloc = 0;
	}

	struct block_meta *block;

	type = 1;
	if (size <= 0)
		return NULL;

	if (size + METADATA_SIZE < page_size)
		type = 0;

	if (!head && type == 0) {
		block = request_space(NULL, 128 * 1024 - METADATA_SIZE);
		if (!block)
			return NULL;

		head = block;
		last = head;
		last->prev = NULL;
		last->next = NULL;
	} else {
		block = NULL;
		if (head)
			block = find_best(size);

		if (!block) {
			if (head)
				last = get_last(head);
			block = request_space(last, size);
			if (!block)
				return NULL;
		} else {
			block->status = type + 1;
			split_block(block, size);
		}
	}
	return block + 1;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

	struct block_meta *block_ptr = get_block_ptr(ptr), *prev = NULL,
						*next = NULL;
	size_t size = block_ptr->size;

	prev = block_ptr->prev;
	next = block_ptr->next;
	void *adjusted_ptr = (void *)((uintptr_t)ptr - METADATA_SIZE);

	if (block_ptr->status == STATUS_MAPPED) {
		if (prev && next) {
			prev->next = next;
			prev->next->prev = prev;
			prev->size += ALIGN(size + METADATA_SIZE);
		} else if (prev) {
			prev->next = NULL;
			prev->size += ALIGN(size + METADATA_SIZE);
		}
		munmap(adjusted_ptr, ALIGN(size + METADATA_SIZE));
	} else {
		block_ptr->status = STATUS_FREE;
		coalescing_list(&block_ptr);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;

	coming_from_calloc = 1;

	void *ptr = os_malloc(total_size);

	memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = get_block_ptr(ptr);

	if (block->status == STATUS_FREE)
		return NULL;

	if (block->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(size);

		if (!new_ptr)
			return NULL;
		memcpy(new_ptr, ptr, block->size < size ? block->size : size);
		os_free(ptr);
		return new_ptr;
	}

	if (block->size >= size) {
		split_block(block, size);
		return ptr;
	}

	if (block->next && block->next->status == STATUS_FREE &&
		block->size + block->next->size + METADATA_SIZE >= size) {
		coalescing_list(&block);
		split_block(block, size);
		return ptr;
	}

	if (!block->next) {
		expand_block(block, size, block->size);
		return ptr;
	}

	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;
	memcpy(new_ptr, ptr, block->size);
	os_free(ptr);
	return new_ptr;
}

struct block_meta *get_block_ptr(void *ptr)
{
	return (struct block_meta *)ptr - 1;
}

struct block_meta *get_last(struct block_meta *head)
{
	struct block_meta *aux = head;

	while (aux->next)
		aux = aux->next;
	return aux;
}

struct block_meta *get_head(struct block_meta *block)
{
	struct block_meta *aux = block;

	while (aux->prev)
		aux = aux->prev;
	return aux;
}

void expand_block(struct block_meta *block, size_t size, size_t current_size)
{
	struct block_meta *behind = NULL;
	size_t total_size = ALIGN(current_size);
	size_t total_size2 = ALIGN(size);

	current_size = total_size2 - total_size;
	behind = block->prev;
	void *request = sbrk(current_size);

	if (request == (void *)-1)
		return;

	block->size = size;
	block->status = STATUS_ALLOC;
	block->next = NULL;
	if (behind) {
		behind->next = block;
		block->prev = behind;
	}
}

void coalescing_list(struct block_meta **block)
{
	if ((*block)->next && (*block)->next->status == STATUS_FREE) {
		(*block)->size += (*block)->next->size + METADATA_SIZE;
		(*block)->next = (*block)->next->next;

		if ((*block)->next)
			(*block)->next->prev = (*block);
	}

	if ((*block)->prev && (*block)->prev->status == STATUS_FREE) {
		(*block)->prev->size += (*block)->size + METADATA_SIZE;
		(*block)->prev->next = (*block)->next;

		if ((*block)->next)
			(*block)->next->prev = (*block)->prev;
	}
}

void split_block(struct block_meta *block, size_t size)
{
	size_t remaining_size = ALIGN(block->size) - ALIGN(size);

	if (remaining_size >= ALIGN(METADATA_SIZE + 1)) {
		struct block_meta *new_block =
				(struct block_meta *)((char *)block + ALIGN(size) + METADATA_SIZE);

		new_block->size = ALIGN(remaining_size) - METADATA_SIZE;
		new_block->status = STATUS_FREE;
		new_block->prev = block;
		new_block->next = block->next;
		block->size = size;
		block->next = new_block;
		if (new_block->next)
			new_block->next->prev = new_block;
		coalescing_list(&new_block);
	}
}

struct block_meta *find_best(size_t size)
{
	struct block_meta *current = head;
	size_t min_size = 128 * 1024;
	struct block_meta *min_current = NULL;
	int n = 0;

	while (current->next) {
		if (current->status == STATUS_FREE && current->size >= size &&
			current->size - size < min_size) {
			min_size = current->size - size;
			min_current = current;
		}
		n++;
		if (n > 30)
			break;
		current = current->next;
	}
	if (current->status == STATUS_FREE && current->size >= size &&
		current->size - size < min_size) {
		min_size = current->size - size;
		min_current = current;
	}
	if (current->status == STATUS_FREE && current->size < size &&
		!min_current) {
		min_current = current;
		expand_block(min_current, size, current->size);
	}

	return min_current;
}

struct block_meta *request_space(struct block_meta *last, size_t size)
{
	size_t total_size = ALIGN(size + METADATA_SIZE);

	struct block_meta *block;

	if (type + 1 == STATUS_ALLOC) {
		block = sbrk(0);
		void *request = sbrk(total_size);

		if (request == (void *)-1)
			return NULL;
	} else {
		block =
			(struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE,
										MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (block == MAP_FAILED)
			return NULL;
	}
	if (last) {
		last->next = block;
		block->prev = last;
		last->next->prev = last;
	}
	block->size = size;
	block->next = NULL;
	block->status = type + 1;

	return block;
}

void coalesce_all(void)
{
	struct block_meta *cursor = head;

	while (cursor->next) {
		if (cursor->status == STATUS_FREE)
			coalescing_list(&cursor);
		cursor = cursor->next;
	}
}
