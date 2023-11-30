// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * TODO 1/0: Fill in name / email
 * Author: FirstName LastName <user@email.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

/*
 * Command actions (addf, adde, delf, dela).
 */
// Action length
#define ACTION_LEN			4
// Action add first
#define ACTION_ADDF			"addf"
// Action add end
#define ACTION_ADDE			"adde"
// Action delete first
#define ACTION_DELF			"delf"
// Action delete all
#define ACTION_DELA			"dela"
// Command name offset (after action length and space)
#define NAME_OFFSET			(ACTION_LEN + 1)

/*
 * Data structure for commands names.
 */
struct name_t {
	char *buf;				// buffer to store command name
	struct list_head list;	// entry for kernel_api_list
};

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/*
 * Define kernel api list.
 */
LIST_HEAD(kernel_api_list);

/* Allocate memory and complete buf for a kernel api list entry.
 *
 * @buf		: Buffer to be stored in list entry buf.
 * @err		: Error to be filled by function on error.
 *
 * Return 0 on success and -ENOMEM if no memory left.
 */
static struct name_t *entry_create(char *buf, ssize_t *err)
{
	struct name_t *entry = NULL;

	// Alloc space for list entry
	entry = kmalloc(sizeof(struct name_t), GFP_KERNEL);
	if (!entry) {
		*err = -ENOMEM;
		return NULL;
	}

	// Alloc space (and fill) entry buffer
	entry->buf = kstrdup(buf, GFP_KERNEL);
	if (!entry->buf) {
		kfree(entry);
		entry = NULL;
		*err = -ENOMEM;
		return NULL;
	}

	return entry;
}

/* Free list memory. */
static void destroy_list(void)
{
	struct list_head *i, *aux;

	list_for_each_safe(i, aux, &kernel_api_list) {
		// Get list entry
		struct name_t *entry = list_entry(i, struct name_t, list);

		list_del(i);
		kfree(entry->buf);
		kfree(entry);
		entry = NULL;
	}
}

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *i;

	list_for_each(i, &kernel_api_list) {
		struct name_t *entry = list_entry(i, struct name_t, list);

		seq_puts(m, entry->buf);
		seq_puts(m, "\n");
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char *name;
	ssize_t rv = 0;
	struct list_head *i, *aux;
	struct name_t *entry = NULL;
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	// Remove newline from end of the name
	local_buffer[local_buffer_size-1] = '\0';
	// Save name from command (only used if valid action is found)
	name = local_buffer + NAME_OFFSET;

	// Add first command
	if (!memcmp(local_buffer, ACTION_ADDF, ACTION_LEN)) {
		// Create list entry
		entry = entry_create(name, &rv);
		if (!entry)
			return rv;

		// Add entry to list head
		list_add(&entry->list, &kernel_api_list);

		return local_buffer_size;
	}

	// Add end command
	if (!memcmp(local_buffer, ACTION_ADDE, ACTION_LEN)) {
		// Create list entry
		entry = entry_create(name, &rv);
		if (!entry)
			return rv;

		// Add entry to list tail
		list_add_tail(&entry->list, &kernel_api_list);

		return local_buffer_size;
	}

	// Delete first command
	if (!memcmp(local_buffer, ACTION_DELF, ACTION_LEN)) {
		list_for_each_safe(i, aux, &kernel_api_list) {
			// Get list entry
			entry = list_entry(i, struct name_t, list);
			// Check if entry has to be removed
			if ((strlen(name) == strlen(entry->buf)) &&
				(strcmp(name, entry->buf) == 0)) {

				list_del(i);
				kfree(entry->buf);
				kfree(entry);
				entry = NULL;
				break;
			}
		}

		return local_buffer_size;
	}

	// Delete all command
	if (!memcmp(local_buffer, ACTION_DELA, ACTION_LEN)) {
		list_for_each_safe(i, aux, &kernel_api_list) {
			// Get list entry
			entry = list_entry(i, struct name_t, list);
			// Check if entry has to be removed
			if ((strlen(name) == strlen(entry->buf)) &&
				(strcmp(name, entry->buf) == 0)) {

				list_del(i);
				kfree(entry->buf);
				kfree(entry);
				entry = NULL;
			}
		}

		return local_buffer_size;
	}

	// Wrong command action
	return -EINVAL;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
	// Free list memory
	destroy_list();
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
/* TODO 5: Fill in your name / email address */
MODULE_AUTHOR("FirstName LastName <your@email.com>");
MODULE_LICENSE("GPL v2");
