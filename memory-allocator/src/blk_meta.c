// SPDX-License-Identifier: BSD-3-Clause

#include "defines.h"
#include "blk_meta.h"


/*****************************************************************************/

void *blk_meta_get_end_addr(struct block_meta *blk)
{
	return ADDR_ALIGN((void *)blk + MEM_SIZE_ALIGN(blk_meta_get_size(blk)));
}


/*****************************************************************************/

void *blk_meta_get_payload_addr(struct block_meta *blk)
{
	return ADDR_ALIGN((void *)blk + META_SIZE_ALIGN);
}


/*****************************************************************************/

void blk_meta_set_size(struct block_meta *blk, size_t size)
{
	blk->size = size;
}

size_t blk_meta_get_size(struct block_meta *blk)
{
	return blk->size;
}


/*****************************************************************************/

void blk_meta_set_status(struct block_meta *blk, int status)
{
	blk->status = status;
}

int blk_meta_get_status(struct block_meta *blk)
{
	return blk->status;
}

//
void blk_meta_set_free(struct block_meta *blk)
{
	blk->status = STATUS_FREE;
}

//
int blk_meta_is_free(struct block_meta *blk)
{
	return blk->status == STATUS_FREE;
}

//
void blk_meta_set_alloc(struct block_meta *blk)
{
	blk->status = STATUS_ALLOC;
}

int blk_meta_is_alloc(struct block_meta *blk)
{
	return blk->status == STATUS_ALLOC;
}

//
void blk_meta_set_mapped(struct block_meta *blk)
{
	blk->status = STATUS_MAPPED;
}

int blk_meta_is_mapped(struct block_meta *blk)
{
	return blk->status == STATUS_MAPPED;
}


/*****************************************************************************/

void blk_meta_init(struct block_meta *blk, size_t size, int status)
{
	blk_meta_set_size(blk, size);
	blk_meta_set_status(blk, status);
	blk->next = blk->prev = blk;
}

void blk_meta_print(struct block_meta *blk)
{
	printf("block(%p)\n", blk);
	printf("    status       = %d\n", blk_meta_get_status(blk));
	printf("    payload size = %d\n", blk_meta_get_size(blk));
	printf("    payload addr = %p\n", blk_meta_get_payload_addr(blk));
}
