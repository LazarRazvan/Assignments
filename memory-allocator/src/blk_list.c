// SPDX-License-Identifier: BSD-3-Clause

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "defines.h"
#include "blk_meta.h"
#include "blk_list.h"


/*****************************************************************************/
//
// GLOBALS
//

// list of brk blocks (allocated and free)
struct block_meta *brk_head = NULL;

// list of mmap block (mapped)
struct block_meta *map_head = NULL;


/*****************************************************************************/
//
// CONTIGOUS VALIDATION FOR BRK BLOCKS
//

#ifdef CONTIGUOUS_VALIDATE
static void
__heap_contigous_validate(struct block_meta *prev, struct block_meta *crt)
{
	// do not validate if current block is head
	if (crt == brk_head)
		return;

	//
	if (blk_meta_is_mapped(prev) || blk_meta_is_mapped(crt))
		DIE(1, "Mapped memory in brk memory blocks!\n");

	// validation
	if (blk_meta_get_end_addr(prev) != (void *)crt) {
		printf("block (%p) overlapping block (%p)\n", prev, crt);
		assert(0);
	}
}
#endif

static void __blk_list_contiguous_validate(void)
{
#ifdef CONTIGUOUS_VALIDATE
	struct block_meta *it;

	if (!brk_head)
		return;

	//
	it = brk_head;
	while(it->next != brk_head) {
		__heap_contigous_validate(it->prev, it);
		it = it->next;
	}

	__heap_contigous_validate(it->prev, it);
#endif
}


/*****************************************************************************/

static void
__blk_list_add_tail(struct block_meta **list, struct block_meta *blk)
{
	if (!*list) {
		*list = blk;
		blk->next = *list;
		blk->prev = *list;
	} else {
		blk->next = *list;
		blk->prev = (*list)->prev;
		(*list)->prev->next = blk;
		(*list)->prev = blk;
	}
}

static void
__blk_list_add_after(struct block_meta *prev, struct block_meta *crt)
{
	crt->next = prev->next;
	crt->prev = prev;
	prev->next->prev = crt;
	prev->next = crt;
}

static void
__blk_list_delete(struct block_meta **list, struct block_meta *blk)
{
	if (blk == *list) {
		// check if only element in list
		if ((*list)->next == *list) {
			*list = NULL;
			return;
		} else {
			*list = (*list)->next;
		}
	}

	blk->prev->next = blk->next;
	blk->next->prev = blk->prev;
}

static struct block_meta *
__blk_list_lookup_by_payload_addr(struct block_meta *list, void *addr)
{
	struct block_meta *it = NULL;

	if (!list)
		return NULL;

	it = list;
	while(it->next != list) {
		if (blk_meta_get_payload_addr(it) == addr)
			return it;

		it = it->next;
	}

	if (blk_meta_get_payload_addr(it) == addr)
		return it;

	return NULL;
}

static void
__blk_list_print(struct block_meta *list)
{
	struct block_meta *it;

	if (!list) {
		printf("Empty list!\n");
		return;
	}

	//
	it = list;
	while(it->next != list) {
		blk_meta_print(it);
		it = it->next;
	}

	blk_meta_print(it);
}

static void
__blk_list_rprint(struct block_meta *list)
{
	struct block_meta *it;

	if (!list) {
		printf("Empty list!\n");
		return;
	}

	//
	it = list;
	while(it->prev != list) {
		blk_meta_print(it);
		it = it->prev;
	}

	blk_meta_print(it);
}


/*****************************************************************************/


void blk_list_add_tail(struct block_meta *blk)
{
	DIE(!blk, "Invalid block for tail add!\n");
	//
	switch (blk_meta_get_status(blk)) {
	case STATUS_FREE:
	case STATUS_ALLOC:
		__blk_list_add_tail(&brk_head, blk);
		__blk_list_contiguous_validate();
		break;
	case STATUS_MAPPED:
		__blk_list_add_tail(&map_head, blk);
		break;
	default:
		DIE(1, "Invalid block status for tail add!\n");
	}
}

void blk_list_add_after(struct block_meta *prev, struct block_meta *crt)
{
	DIE(!prev, "Invalid prev block for after add!\n");
	DIE(!crt, "Invalid crt block for after add!\n");
	//
	switch (blk_meta_get_status(prev)) {
	case STATUS_FREE:
	case STATUS_ALLOC:
		DIE(blk_meta_is_mapped(crt), "Invalid mapped block in brk list!\n");
		//
		__blk_list_add_after(prev, crt);
		__blk_list_contiguous_validate();
		break;
	case STATUS_MAPPED:
		DIE(blk_meta_is_free(crt), "Invalid brk block in mapped list!\n");
		DIE(blk_meta_is_alloc(crt), "Invalid brk block in mapped list!\n");
		//
		__blk_list_add_after(prev, crt);
		break;
	default:
		DIE(1, "Invalid block status for after add!\n");
	}
}


/*****************************************************************************/

void blk_list_delete(struct block_meta *blk)
{
	DIE(!blk, "Invalid block for delete!\n");
	//
	switch (blk_meta_get_status(blk)) {
	case STATUS_FREE:
	case STATUS_ALLOC:
		__blk_list_delete(&brk_head, blk);
		__blk_list_contiguous_validate();
		break;
	case STATUS_MAPPED:
		__blk_list_delete(&map_head, blk);
		break;
	default:
		DIE(1, "Invalid block status for delete!\n");
	}
}


/*****************************************************************************/

// brk list only
struct block_meta *blk_list_get_best_free(size_t data_size)
{
	struct block_meta *it = NULL;
	struct block_meta *best = NULL;
	size_t blk_payload_size, delta = SIZE_MAX;

	if (!brk_head) {
		return NULL;
	}

	//
	it = brk_head;
	while(it->next != brk_head) {
		if (!blk_meta_is_free(it)) {
			it = it->next;
			continue;
		}

		blk_payload_size = PAYLOAD_SIZE_ALIGN(blk_meta_get_size(it));
		if (blk_payload_size >= data_size && blk_payload_size < delta) {
			delta = blk_payload_size;
			best = it;
		}

		it = it->next;
	}

	if (blk_meta_is_free(it)) {
		blk_payload_size = PAYLOAD_SIZE_ALIGN(blk_meta_get_size(it));
		if (blk_payload_size >= data_size && blk_payload_size < delta) {
			best = it;
		}
	}

	return best;
}

// brk list only
struct block_meta *blk_list_get_last(void)
{
	if (!brk_head)
		return NULL;

	return brk_head->prev;
}


/*****************************************************************************/

// brk list only
int blk_list_coallesce_next(struct block_meta *blk)
{
	struct block_meta *blk_next = NULL;

	// do not coallesce if current block is not free
	if (!blk || !blk_meta_is_free(blk))
		goto no_coallesce;

	// do not coallesce if next block is head or is not free
	blk_next = blk->next;
	if (blk_next == brk_head || !blk_meta_is_free(blk_next))
		goto no_coallesce;

	// coallesce blocks
	blk->next = blk_next->next;
	blk->next->prev = blk;

	// update block size
	blk_meta_set_size(blk, PAYLOAD_SIZE_ALIGN(blk_meta_get_size(blk)) +
							MEM_SIZE_ALIGN(blk_meta_get_size(blk_next)));

	return 1;

no_coallesce:
	return 0;
}

// brk list only
void blk_list_coallesce_all(void)
{
	struct block_meta *it = NULL;

	if (!brk_head)
		return;

	// wait on each free block until coallesce all blocks
	it = brk_head;
	while(it->next != brk_head) {
		if (!blk_list_coallesce_next(it))
			it = it->next;
	}
}


/*****************************************************************************/

// brk list only
int blk_list_merge_next(struct block_meta *blk)
{
	struct block_meta *blk_next = NULL;

	if (!blk)
		goto no_merge;

	// do not coallesce if next block is head or is not free
	blk_next = blk->next;
	if (blk_next == brk_head || !blk_meta_is_free(blk_next))
		goto no_merge;

	// coallesce blocks
	blk->next = blk_next->next;
	blk->next->prev = blk;

	// update block size
	blk_meta_set_size(blk, PAYLOAD_SIZE_ALIGN(blk_meta_get_size(blk)) +
							MEM_SIZE_ALIGN(blk_meta_get_size(blk_next)));

	return 1;

no_merge:
	return 0;
}


/*****************************************************************************/

struct block_meta *blk_list_lookup_by_payload_addr(void *addr)
{
	struct block_meta *blk;

	// brk list lookup
	blk = __blk_list_lookup_by_payload_addr(brk_head, addr);
	if (blk)
		return blk;

	// map list lookup
	blk = __blk_list_lookup_by_payload_addr(map_head, addr);
	if (blk)
		return blk;

	return NULL;
}


/*****************************************************************************/

void blk_list_print(void)
{
	// brk list
	printf("BRK LIST:\n");
	__blk_list_print(brk_head);

	// map list
	printf("MAP LIST:\n");
	__blk_list_print(map_head);
}

void blk_list_rprint(void)
{
	// brk list
	printf("BRK REVERSE LIST:\n");
	__blk_list_rprint(brk_head);

	// map list
	printf("BRK REVERSE LIST:\n");
	__blk_list_rprint(map_head);
}

int blk_list_brk_is_empty(void)
{
	return brk_head ? 0 : 1;
}

int blk_list_map_is_empty(void)
{
	return map_head ? 0 : 1;
}
