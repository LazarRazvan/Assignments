/*
 * Executable Parser Header
 *
 * 2018, Operating Systems
 */

#ifndef SO_SEGMENT_H_
#define SO_SEGMENT_H_

#include "exec_parser.h"

// Page is mapped inside segment
#define PAGE_MAPPED						1

// Page is not mapped inside segment
#define PAGE_NOT_MAPPED					0

// Round up division for pages inside a segment.
#define DIV_ROUND_UP(n, d)				(((n) + (d) - 1) / (d))

// Segment start address
#define SO_SEG_START(seg)				(seg->vaddr)

// Segment end address
#define SO_SEG_END(seg)					(seg->vaddr + seg->mem_size)

// Segment file end address
#define SO_SEG_FEND(seg)				((void *)(seg->vaddr + seg->file_size))

/**
 * Structure to track mapped pages for each segment.
 *
 * If mapped_pages[i] is 1 then page was already mapped, otherwise
 * page has to be mapped.
 */

typedef struct seg_data {
	/* segment pages no */
	unsigned int	pages_no;
	/* array of segment pages */
	char			*mapped_pages;
} seg_data_t;

/* Initialize a segment data */
int so_seg_data_init(so_seg_t *seg);

/* Free data for a segment */
void so_seg_data_free(so_seg_t *seg);

/* Get page id inside segment */
int so_seg_get_page_id(so_seg_t *seg, uintptr_t f_addr);

/* Get page mapped inside segment */
char so_seg_get_page_mapped(so_seg_t *seg, int page_id);

/* Set a page as mapped inside segment */
void so_seg_set_page_mapped(so_seg_t *seg, int page_id);

/* Get page staring address based on page id */
void *so_seg_get_page_addr(so_seg_t *seg, int page_id);

/* Get actual size of page that has to be filled */
int so_seg_get_page_asize(so_seg_t *seg, int page_id);

/* Get file offset based on segment page */
off_t so_seg_get_file_off(so_seg_t *seg, int page_id);

#endif /* SO_SEGMENT_H_ */
