// SPDX-License-Identifier: BSD-3-Clause

#include "block_meta.h"


/*****************************************************************************/

void *blk_meta_get_end_addr(struct block_meta *blk);

/*****************************************************************************/

void *blk_meta_get_payload_addr(struct block_meta *blk);

/*****************************************************************************/

void blk_meta_set_size(struct block_meta *blk, size_t size);
size_t blk_meta_get_size(struct block_meta *blk);

/*****************************************************************************/

void blk_meta_set_status(struct block_meta *blk, int status);
int blk_meta_get_status(struct block_meta *blk);
//
void blk_meta_set_free(struct block_meta *blk);
int blk_meta_is_free(struct block_meta *blk);
//
void blk_meta_set_alloc(struct block_meta *blk);
int blk_meta_is_alloc(struct block_meta *blk);
//
void blk_meta_set_mapped(struct block_meta *blk);
int blk_meta_is_mapped(struct block_meta *blk);


/*****************************************************************************/

void blk_meta_init(struct block_meta *blk, size_t size, int status);
void blk_meta_print(struct block_meta *blk);
