// SPDX-License-Identifier: BSD-3-Clause

#include "block_meta.h"


/*****************************************************************************/

void blk_list_add_tail(struct block_meta *blk);
void blk_list_add_after(struct block_meta *prev, struct block_meta *crt);

/*****************************************************************************/

void blk_list_delete(struct block_meta *blk);

/*****************************************************************************/

struct block_meta *blk_list_get_best_free(size_t data_size);
struct block_meta *blk_list_get_last(void);

/*****************************************************************************/

int blk_list_coallesce_next(struct block_meta *blk);
void blk_list_coallesce_all(void);

/*****************************************************************************/

int blk_list_merge_next(struct block_meta *blk);

/*****************************************************************************/

struct block_meta *blk_list_lookup_by_payload_addr(void *addr);

/*****************************************************************************/

int blk_list_brk_is_empty(void);
int blk_list_map_is_empty(void);

/*****************************************************************************/

void blk_list_print(void);
void blk_list_rprint(void);
