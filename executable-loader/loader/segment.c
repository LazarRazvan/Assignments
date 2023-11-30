/*
 * Executable Parser Implementation
 *
 * 2018, Operating Systems
 */

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "segment.h"

/**
 * Initalize a segment data.
 *
 * @seg	: Segment to be initialized.
 *
 * Return 0 on success and <0 otherwise.
 */
int so_seg_data_init(so_seg_t *seg)
{
	seg_data_t *seg_data = NULL;
	size_t page_size = getpagesize();

	if (seg->data)
		return -1;

	/* Alloc data section inside segment */
	seg_data = malloc(sizeof(seg_data_t));
	if (!seg_data)
		return -2;

	/* Compute total number of pages in segment */
	seg_data->pages_no = DIV_ROUND_UP(seg->mem_size, page_size);

	/* Alloc and init to 0 (not mapped) all pages */
	seg_data->mapped_pages = calloc(seg_data->pages_no, sizeof(char));
	if (!seg_data->mapped_pages) {
		free(seg_data);
		return -3;
	}

	seg->data = seg_data;

	return 0;
}

/**
 * Free a segment data.
 *
 * @seg	: Segment to be freed.
 *
 * Return 0 on success and <0 otherwise.
 */
void so_seg_data_free(so_seg_t *seg)
{
	seg_data_t *seg_data = NULL;

	/* Segment data was not initialized */
	if (seg->data)
		return;

	seg_data = (seg_data_t *)seg->data;
	free(seg_data->mapped_pages);
	free(seg_data);
}

/**
 * Get page id inside a segment.
 * Substract segment start address from faulting address and divide to page
 * size.
 *
 * @seg		: Segment page fault was generated in.
 * @f_addr	: Faulting address.
 *
 * Return page id inside segment.
 */
int so_seg_get_page_id(so_seg_t *seg, uintptr_t f_addr)
{
	size_t page_size = getpagesize();

	return (f_addr - SO_SEG_START(seg)) / page_size;
}

/**
 * Get page mapped inside segment.
 *
 * @seg		: Segment page fault was generated in.
 * @page_id	: Page id inside segment pages.
 *
 * Return status.
 */
char so_seg_get_page_mapped(so_seg_t *seg, int page_id)
{
	seg_data_t *seg_data = (seg_data_t *)seg->data;

	return seg_data->mapped_pages[page_id];
}

/**
 * Set page mapped inside segment.
 *
 * @seg		: Segment page fault was generated in.
 * @page_id	: Page id inside segment pages.
 */
void so_seg_set_page_mapped(so_seg_t *seg, int page_id)
{
	seg_data_t *seg_data = (seg_data_t *)seg->data;

	seg_data->mapped_pages[page_id] = PAGE_MAPPED;
}

/**
 * Get page starting address based on page id.
 * Page starting address inside a segment is computed by getting the offset
 * relative to segment starting address.
 *
 * @seg		: Segment page fault was generated in.
 * @page_id	: Page id inside segment pages.
 *
 * Return page address.
 */
void *so_seg_get_page_addr(so_seg_t *seg, int page_id)
{
	size_t page_size = getpagesize();

	return (void *)(seg->vaddr + page_id * page_size);
}

/**
 * Get actual size of a page that has to be filled.
 * Get page bytes that are inside segment file_size.
 *
 * @seg		: Segment page fault was generated in.
 * @page_id	: Page id inside segment pages.
 *
 * Return page bytes to be filled with data from file.
 */
int so_seg_get_page_asize(so_seg_t *seg, int page_id)
{
	size_t page_size = getpagesize();
	void *page_saddr = so_seg_get_page_addr(seg, page_id);

	/**
	 * Case 1: Page is entirely inside file_size.
	 * Entire page will be filled with data from file.
	 */
	if (page_saddr + page_size <= SO_SEG_FEND(seg))
		return page_size;

	/**
	 * Case 2: Page is partial inside file_size.
	 * Page will be filled with data only to file_size.
	 */
	if (page_saddr < SO_SEG_FEND(seg) &&
		page_saddr + page_size > SO_SEG_FEND(seg))
		return SO_SEG_FEND(seg) - page_saddr;

	/**
	 * Case 3: Page is totally outsilde file_size.
	 * 0 data will be filled from file.
	 */
	return 0;
}

/**
 * Get file offset based on segment page.
 * When moving data from file to a segment page we have to also take
 * into account page offset relative to segment offset.
 *
 * @seg		: Segment page fault was generated in.
 * @page_id	: Page id inside segment pages.
 *
 * Return file offset for the given page.
 */
off_t so_seg_get_file_off(so_seg_t *seg, int page_id)
{
	size_t page_size = getpagesize();

	return seg->offset + page_id * page_size;
}
