/*
 * SO2 kprobe based tracer info header file
 */

#ifndef TRACER_INFO_H__
#define TRACER_INFO_H__ 1

/**
 * API for tracer_proc_info struct.
 */

// Entries
int tracer_info_add_entry(pid_t pid);
int tracer_info_delete_entry(pid_t pid);

// Show
int tracer_info_show(struct seq_file *m, void *v);

// Init
int tracer_info_init(void);

// Deinit
void tracer_info_deinit(void);

#endif /* TRACER_INFO_H_ */
