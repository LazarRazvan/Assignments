// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include "osmem.h"
#include "defines.h"
#include "blk_list.h"
#include "blk_meta.h"


/*****************************************************************************/
//
// MMAP
//

/**
 * Allocate "size" bytes using mmap.
 *
 * Return heap address on heap and NULL on error.
 */
static void *__os_mmap_alloc(size_t size)
{
	return mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1,
				0);
}

/**
 * Free "size" bytes using munmap.
 */
static void __os_mmap_free(void *ptr, size_t size)
{
	DIE(munmap(ptr, size) == -1, "Unmap failed!\n");
}


/*****************************************************************************/
//
// BRK
//

/**
 * Allocate "size" bytes on heap using brk.
 *
 * Return heap address on heap and NULL on error.
 */
static void *__os_brk_alloc(size_t size)
{
	void *addr = NULL;

	addr = sbrk(0);
	sbrk(size);

	// validate returned memory size
	DIE((size_t)(sbrk(0) - addr) != size, "Heap allocation error!");

	return addr;
}

/**
 * Try reusing the best free memory block for "size" bytes. The best memory
 * block is considered to be the smallest to fit "size" bytes.
 *
 * To reduce the internal memory fragmentation, if the remaining memory is
 * enough for a new memory block (block meta and at least 1 byte of data),
 * the block is splitted and a new free memory block is added.
 *
 * Return payload address of the block to reuse on success and NULL if none of
 * the blocks can be reuse.
 */
static void *__os_brk_get_best_free(size_t size)
{
	size_t block_size, left_size;
	struct block_meta *block = NULL;
	struct block_meta *new_block = NULL;

	// coallesce the blocks first
	blk_list_coallesce_all();

	// best free block lookup
	block = blk_list_get_best_free(size);
	if (!block)
		return NULL;

	// block split if necessary
	block_size = blk_meta_get_size(block);
	left_size = PAYLOAD_SIZE_ALIGN(block_size) - PAYLOAD_SIZE_ALIGN(size);
	//
	if (left_size >= MIN_BLOCK_SIZE) {
		// update size of base block
		blk_meta_set_size(block, size);

		new_block = (struct block_meta *)((void *)block + MEM_SIZE_ALIGN(size));
		blk_meta_init(new_block, left_size - META_SIZE_ALIGN, STATUS_FREE);
		blk_list_add_after(block, new_block);
	}

	// mark block as allocated
	blk_meta_set_alloc(block);

	return blk_meta_get_payload_addr(block);
}

/**
 * If no block can be rused, as per implementation requirements, the last block
 * has to be increased to fit "size" bytes if it is free.
 *
 * Return payload address of the last block if it is free and successfully
 * expanded and NULL oterwise.
 */
static void *__os_brk_increase_last(size_t size)
{
	size_t block_size, extra_size;
	struct block_meta *block = NULL;

	// get last block
	block = blk_list_get_last();
	if (!block)
		return NULL;

	// if not free, cannot be expanded
	if (!blk_meta_is_free(block))
		return NULL;

	// compute extra size
	block_size = blk_meta_get_size(block);
	DIE(PAYLOAD_SIZE_ALIGN(size) < PAYLOAD_SIZE_ALIGN(block_size),
			"Invalid size to expand last free block!");
	//
	extra_size = PAYLOAD_SIZE_ALIGN(size) - PAYLOAD_SIZE_ALIGN(block_size);

	// increase heap size
	DIE(!__os_brk_alloc(extra_size), "Unable to expand last block!\n");

	// update block metadata
	blk_meta_set_alloc(block);
	blk_meta_set_size(block, size);

	return blk_meta_get_payload_addr(block);
}

/**
 * Alloc a new memory block. As per implementation requirements, the first
 * alloc increase heap with 128 bytes (ignoring actual size) and split the
 * memory to reduce overhead for futher allocations.
 *
 * Return payload address on success and NULL otherwise
 */
static void *__os_brk_new(size_t size)
{
	void *addr = NULL;
	size_t total_size, left_size;
	struct block_meta *block = NULL;
	struct block_meta *new_block = NULL;

	// compute total size (check first allocation)
	total_size = blk_list_brk_is_empty() ?
									FIRST_BLOCK_SIZE : MEM_SIZE_ALIGN(size);

	// increase heap size
	addr = __os_brk_alloc(total_size);
	DIE(!addr, "Unable to alloc block!\n");

	// set block metadata
	block = (struct block_meta *)ADDR_ALIGN(addr);
	blk_meta_init(block, total_size - META_SIZE_ALIGN, STATUS_ALLOC);
	blk_list_add_tail(block);

	// split block if necessary
	left_size = total_size - MEM_SIZE_ALIGN(size);
	if (left_size >= MIN_BLOCK_SIZE) {
		blk_meta_set_size(block, size);
		//
		new_block = (struct block_meta *)((void *)block + MEM_SIZE_ALIGN(size));
		blk_meta_init(new_block, left_size - META_SIZE_ALIGN, STATUS_FREE);
		blk_list_add_tail(new_block);
	}

	return blk_meta_get_payload_addr(block);
}


/*****************************************************************************/
//
// MALLOC
//

static void *__os_malloc_brk(size_t size)
{
	void *addr = NULL;

	/******************************************************
	 * Try block reuse after coallesce.
	 ******************************************************/
	addr = __os_brk_get_best_free(size);
	if (addr)
		goto success;

	/******************************************************
	 * Try increase last block (if free).
	 ******************************************************/
	addr = __os_brk_increase_last(size);
	if (addr)
		goto success;

	/******************************************************
	 * Alloc memory for a new block (metadata + payload).
	 ******************************************************/
	addr = __os_brk_new(size);
	if (addr)
		goto success;

	return NULL;

success:
	return addr;
}

static void *__os_malloc_mmap(size_t size)
{
	void *addr = NULL;
	struct block_meta *block = NULL;

	/******************************************************
	 * Alloc memory for a new block (metadata + payload)
	 * using mmap.
	 *
	 * Set block size as given and mark it as MAPPED.
	 ******************************************************/
	addr = __os_mmap_alloc(MEM_SIZE_ALIGN(size));
	DIE(!addr, "mmap allocation failed!\n");

	//
	block = (struct block_meta *)ADDR_ALIGN(addr);
	blk_meta_init(block, size, STATUS_MAPPED);
	blk_list_add_tail(block);

	// return payload address
	return blk_meta_get_payload_addr(block);
}


/*****************************************************************************/

static void *__os_calloc_brk(size_t size)
{

	void *addr = NULL;

	/******************************************************
	 * Try block reuse after coallesce.
	 ******************************************************/
	addr = __os_brk_get_best_free(size);
	if (addr)
		goto success;

	/******************************************************
	 * Try increase last block (if free).
	 ******************************************************/
	addr = __os_brk_increase_last(size);
	if (addr)
		goto success;

	/******************************************************
	 * Alloc memory for a new block (metadata + payload).
	 ******************************************************/
	addr = __os_brk_new(size);
	if (addr)
		goto success;

	return NULL;

success:
	// initialize memory
	memset(addr, 0, size);

	return addr;
}

static void *__os_calloc_mmap(size_t size)
{
	void *addr = NULL;
	struct block_meta *block = NULL;

	/******************************************************
	 * Alloc memory for a new block (metadata + payload)
	 * using mmap.
	 *
	 * Set block size as given and mark it as MAPPED.
	 ******************************************************/
	// allocate memory (metadata + payload)
	addr = __os_mmap_alloc(MEM_SIZE_ALIGN(size));
	DIE(!addr, "mmap allocation failed!\n");

	//
	block = (struct block_meta *)ADDR_ALIGN(addr);
	blk_meta_init(block, size, STATUS_MAPPED);
	blk_list_add_tail(block);

	// zero memory
	memset(blk_meta_get_payload_addr(block), 0, size);

	// return payload address
	return blk_meta_get_payload_addr(block);
}


/*****************************************************************************/

static void *__os_realloc(void *ptr, size_t size)
{
	void *new_addr = NULL;
	void *crt_addr = NULL;
	size_t crt_size, left_size;
	struct block_meta *crt_block = NULL;
	struct block_meta *new_block = NULL;

	//
	DIE(!ptr, "Realloc invalid address!\n");
	DIE(!size, "Realloc invalid size!\n");

	/******************************************************
	 * Memory block lookup (skip if memory is free)
	 ******************************************************/
	crt_block = blk_list_lookup_by_payload_addr(ptr);
	DIE(!crt_block, "Realloc invalid memory!\n");
	//
	crt_size = blk_meta_get_size(crt_block);
	crt_addr = blk_meta_get_payload_addr(crt_block);

	if (blk_meta_is_free(crt_block))
		return NULL;

	/******************************************************
	 * Mapped memory block.
	 *
	 * Do not try to shrink/expand mapped memory blocks.
	 *
	 * 1) alloc new memory block (malloc)
	 * 2) copy current block content to new block
	 * 3) free current block
	 ******************************************************/
	if (blk_meta_is_mapped(crt_block)) {
		// alloc new memory block
		new_addr = os_malloc(size);
		DIE(!new_addr, "realloc memory allocation failed!\n");

		// copy old data
		memcpy(new_addr, crt_addr, MIN(crt_size, size));

		// free current block
		blk_list_delete(crt_block);
		__os_mmap_free(crt_block, MEM_SIZE_ALIGN(crt_size));

		goto success;
	}

	/******************************************************
	 * Alloc memory block (brk).
	 *
	 * Try the following options in turn.
	 *
	 * 1) shrink current memory block
	 * 	1.1) split current block if there is enough left
	 * 	     memory
	 * 2) if new size exceed MMAP_THRESHOLD, alloc memory
	 *    using mmap (no memory blocks exceeding threshold
	 *    are allowed in brk list)
	 * 3) if current block is last block, inplace expand
	 * 4) incremental merge current block (with next free
	 *    blocks) until the new size fits
	 * 	4.1) split current block if there is enough left
	 * 	     memory
	 * 5) alloc a new memory block (os_malloc)
	 ******************************************************/

	// shrink current memory block
	if (PAYLOAD_SIZE_ALIGN(crt_size) >= size) {
		left_size = PAYLOAD_SIZE_ALIGN(crt_size) - PAYLOAD_SIZE_ALIGN(size);

		if (left_size >= MIN_BLOCK_SIZE) {
			// spllit current block
			new_block = (struct block_meta *)((void *)crt_block +
														MEM_SIZE_ALIGN(size));
			blk_meta_init(new_block, left_size - META_SIZE_ALIGN, STATUS_FREE);
			blk_list_add_after(crt_block, new_block);

			// update current block size
			blk_meta_set_size(crt_block, size);
		}

		new_addr = blk_meta_get_payload_addr(crt_block);
		goto success;
	}

	// new memory exceed MMAP_THRESHOLD
	if (MEM_SIZE_ALIGN(size) >= MMAP_THRESHOLD) {
		// alloc new memory block (mapped)
		new_addr = __os_malloc_mmap(size);
		DIE(!new_addr, "realloc memory allocation failed!\n");

		// copy old data
		memcpy(new_addr, crt_addr, MIN(crt_size, size));

		// free current block
		os_free(ptr);

		goto success;
	}

	// last block expand inplace
	if (crt_block == blk_list_get_last()) {
		left_size = PAYLOAD_SIZE_ALIGN(size) - PAYLOAD_SIZE_ALIGN(crt_size);
		DIE(!__os_brk_alloc(left_size), "realloc memory allocation failed!\n");
		//
		blk_meta_set_alloc(crt_block);
		blk_meta_set_size(crt_block, size);

		new_addr = blk_meta_get_payload_addr(crt_block);
		goto success;
	}

	// merge current block
	while (blk_list_merge_next(crt_block)) {
		crt_size = blk_meta_get_size(crt_block);

		if (PAYLOAD_SIZE_ALIGN(crt_size) >= size) {
			left_size = PAYLOAD_SIZE_ALIGN(crt_size) - PAYLOAD_SIZE_ALIGN(size);

			if (left_size >= MIN_BLOCK_SIZE) {
				// split current block
				new_block = (struct block_meta *)((void *)crt_block +
														MEM_SIZE_ALIGN(size));
				blk_meta_init(new_block, left_size - META_SIZE_ALIGN,
																STATUS_FREE);
				blk_list_add_after(crt_block, new_block);

				// update current block size
				blk_meta_set_size(crt_block, size);
			}

			new_addr = blk_meta_get_payload_addr(crt_block);
			goto success;
		}
	}

	// alloc new memory block
	{
		// alloc new memory block
		new_addr = os_malloc(size);
		DIE(!new_addr, "realloc memory allocation failed!\n");

		// copy old data
		memcpy(new_addr, crt_addr, MIN(crt_size, size));

		// free current block
		os_free(ptr);

		goto success;
	}

success:
	DIE(!new_addr, "Unable to realloc block!\n");
	return new_addr;
}


/*****************************************************************************/

void *os_malloc(size_t size)
{
	//
	if (!size)
		return NULL;

	/******************************************************
	 * Use brk for sizes less than threshold, otherwise mmap
	 ******************************************************/
	if (MEM_SIZE_ALIGN(size) < MMAP_THRESHOLD)
		return __os_malloc_brk(size); 
	else
		return __os_malloc_mmap(size);

	return NULL;
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size;

	/******************************************************
	 * null for 0 size or nmemb
	 ******************************************************/
	if (!nmemb || !size)
		return NULL;

	/******************************************************
	 * Use brk for sizes smaller than page_size and mmap
	 * otherwise
	 ******************************************************/
	total_size = nmemb * size;
	if (MEM_SIZE_ALIGN(total_size) < getpagesize())
		return __os_calloc_brk(total_size);
	else
		return __os_calloc_mmap(total_size);

	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/******************************************************
	 * Passing null ptr is same effect as os_malloc(size)
	 ******************************************************/
	if (!ptr)
		return os_malloc(size);

	/******************************************************
	 * Passing 0 as size is same effect as os_free(ptr)
	 ******************************************************/
	if (!size) {
		os_free(ptr);
		return NULL;
	}

	return __os_realloc(ptr, size);
}

void os_free(void *ptr)
{
	size_t block_size;
	struct block_meta *block = NULL;

	if (!ptr)
		return;

	// get associated memory block for address
	block = blk_list_lookup_by_payload_addr(ptr);
	DIE(!block, "Invalid free address!\n");

	//
	block_size = blk_meta_get_size(block);

	/******************************************************
	 * brk memory.
	 *
	 * Set block size to maximum payload size and mark block
	 * as free to be reused.
	 ******************************************************/
	if (blk_meta_is_alloc(block)) {
		blk_meta_set_size(block, PAYLOAD_SIZE_ALIGN(block_size));
		blk_meta_set_free(block);
		goto success;
	}

	/******************************************************
	 * mmap memory.
	 *
	 * Free memory (including metadata) and remove block
	 * from list.
	 ******************************************************/
	if (blk_meta_is_mapped(block)) {
		blk_list_delete(block);
		__os_mmap_free(block, MEM_SIZE_ALIGN(block_size));
		goto success;
	}

	/******************************************************
	 * double free.
	 ******************************************************/
	if (blk_meta_is_free(block)) {
		DIE(1, "Double free!\n");
		goto success; 
	}

	DIE(1, "Unknown free block state!\n");

success:
	return;
}

