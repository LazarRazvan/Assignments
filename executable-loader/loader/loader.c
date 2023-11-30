/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "segment.h"
#include "exec_parser.h"

static so_exec_t *exec;

/* Global file descriptor */
static int global_fd;

/**
 * Demand paging handler. Handler is unset for SIGSEGV signale and decide
 * if it is raised by an error or the page has to be mapped.
 */
static void demand_paging_handler(int signum, siginfo_t *siginfo, void *sigxtra)
{
	ssize_t ret;
	void *page_saddr;
	so_seg_t *seg = NULL;
	int seg_id, seg_page_id, page_asize;
	size_t bytes = 0, page_size = getpagesize();
	uintptr_t f_addr = (uintptr_t)(void *)siginfo->si_addr;

	/**
	 * Get segment id based on faulting address (siginfo->si_addr).
	 *
	 * Iterate in segments list and check if faulting address is between
	 * segment starting address and segment mem size.
	 *
	 *		|.......................................|
	 *		^										^
	 *	seg->vaddr						seg->vaddr + seg->mem_size
	 */
	for (seg_id = 0; seg_id < exec->segments_no; seg_id++) {
		seg = &exec->segments[seg_id];

		if (f_addr >= SO_SEG_START(seg) && f_addr < SO_SEG_END(seg))
			break;
	}

	/* Retrun default handler if faulting address not in segments */
	if (!seg)
		goto default_handler;

	/* Initialize segments if first fault */
	if (!seg->data && so_seg_data_init(seg))
		goto default_handler;

	/* Get page id inside offset */
	seg_page_id = so_seg_get_page_id(seg, f_addr);

	/* Return default handler if faulting address in mapped page */
	if (so_seg_get_page_mapped(seg, seg_page_id) == PAGE_MAPPED)
		goto default_handler;

	/* Get page starting address */
	page_size = getpagesize();
	page_saddr = so_seg_get_page_addr(seg, seg_page_id);

	/**
	 * Map page to memory.
	 * Use write permission at first since we need to move the content from
	 * file to the page. In later step, set page permissions to segment one.
	 */
	if (mmap(page_saddr, page_size, PERM_W,
			MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, global_fd, 0) == MAP_FAILED)
		goto default_handler;

	/**
	 * Move inside file based on segment offset and page id.
	 */
	if (lseek(global_fd, so_seg_get_file_off(seg, seg_page_id), SEEK_SET) == -1)
		goto default_handler;

	/**
	 * Get page actual size that has to be filled with data from file.
	 */
	page_asize = so_seg_get_page_asize(seg, seg_page_id);

	/**
	 * Zero init rest of the page if case.
	 */
	if (page_asize < page_size) {

		if (page_saddr + page_size < (void *)SO_SEG_END(seg))
			memset(page_saddr + page_asize, 0, page_size - page_asize);
		else
			memset(page_saddr + page_asize, 0, ((void *)SO_SEG_END(seg) -
												(page_saddr + page_asize)));
	}

	/**
	 * Page init with data from file if case.
	 */
	while (page_asize) {
		ret = read(global_fd, page_saddr + bytes, page_asize);
		if (ret == -1)
			goto default_handler;

		bytes += ret;
		page_asize -= ret;
	}

	/* Set page deafult permissions */
	mprotect(page_saddr, page_size, seg->perm);

	/* Set page as mapped */
	so_seg_set_page_mapped(seg, seg_page_id);

	return;

default_handler:
	/* Free data allocated for each segment */
	for (seg_id = 0; seg_id < exec->segments_no; seg_id++) {
		seg = &exec->segments[seg_id];
		so_seg_data_free(seg);
	}

	/* Call default SIGSEGV handler */
	signal(SIGSEGV, SIG_DFL);
}

int so_init_loader(void)
{
	struct sigaction sa;

	/* Reset all fields in sigaction */
	memset(&sa, 0, sizeof(sa));

	/* Initialize structure */

	// SA_SIGINGO flags to run sa_sigaction handler
	sa.sa_flags = SA_SIGINFO;

	// sa_sigaction handler
	sa.sa_sigaction = demand_paging_handler;

	/* Register sturcture to SIGSEGV signal */
	sigaction(SIGSEGV, &sa, NULL);

	return -1;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	/* open file for read */
	global_fd = open(path, O_RDONLY);
	if (global_fd == -1)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
