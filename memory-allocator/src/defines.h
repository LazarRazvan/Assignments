// SPDX-License-Identifier: BSD-3-Clause

/**
 * ----------------------------------------------
 * |            |         |           |         |
 * | block_meta | padding |  data     | padding |
 * |            |         |           |         |
 * ----------------------------------------------
 *  <----- METADATA ----->| <------ PAYLOAD ---->
 *
 *  - metadata size has to be aligned to DEFAULT_ALIGN
 *  - payload size has to be aligned to DEFAULT_ALIGN
 *  - block_meta addr has to be aligned to DEFAULT_ALIGN
 *  - data addr has to be aligned to DEFAULT_ALIGN
 */

/*****************************************************************************/
//
// SIZE
//

#define _1kB						(1024)
#define MMAP_THRESHOLD      		(128 * _1kB)
#define FIRST_BLOCK_SIZE			(128 * _1kB)


/*****************************************************************************/
//
// ALIGN
//

#define __ALIGN_MASK(x,mask)    	(((x)+(mask))&~(mask))
#define ALIGN(x,a)              	__ALIGN_MASK(x,(typeof(x))(a)-1)


/*****************************************************************************/
//
// MEMORY BLOCKS
//

#define DEFAULT_ALIGN				(8)
#define META_SIZE					(sizeof(struct block_meta))

#define META_SIZE_ALIGN				(ALIGN(META_SIZE, DEFAULT_ALIGN))
#define PAYLOAD_SIZE_ALIGN(size)	(ALIGN(size, DEFAULT_ALIGN))
#define MEM_SIZE_ALIGN(size)		(META_SIZE_ALIGN + PAYLOAD_SIZE_ALIGN(size))

#define MIN_BLOCK_SIZE				MEM_SIZE_ALIGN(1)

#define ADDR_ALIGN(addr)\
	((void *)(ALIGN((unsigned long)addr, DEFAULT_ALIGN)))


/*****************************************************************************/
//
// UTILS
//

#define MIN(X, Y)					(((X) < (Y)) ? (X) : (Y))
