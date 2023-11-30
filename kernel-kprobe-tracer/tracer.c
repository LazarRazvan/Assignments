// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Tracer
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

#define BUF_MIN_SIZE		5

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/**
 * List.
 */

// Data structure
struct _list {

	char				*name;
	struct list_head	list;

};

// Initialization
LIST_HEAD(name_list);

/**
 * Operations.
 */
#define OP_INLD		-1
#define OP_ADDF		0
#define OP_ADDE		1
#define OP_DELF		2
#define OP_DELA		3

static int list_proc_show(struct seq_file *m, void *v)
{
	struct _list *l;
	struct list_head *_it;

	list_for_each(_it, &name_list) {
		l = list_entry(_it, struct _list, list);
		seq_printf(m, "%s\n", l->name);
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
	int op = OP_INLD;
	struct _list *elem;
	struct list_head *_it, *tmp;
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/**
	 * Return error if buffer is too small. We need at least option,
	 * space and a name ... 5 bytes.
	 */
	if (local_buffer_size < BUF_MIN_SIZE)
		return -EINVAL;

	/**
	 * Validate operation.
	 */
	if (memcmp(local_buffer, "addf", 4) == 0)
		op = OP_ADDF;
	if (memcmp(local_buffer, "adde", 4) == 0)
		op = OP_ADDE;
	if (memcmp(local_buffer, "delf", 4) == 0)
		op = OP_DELF;
	if (memcmp(local_buffer, "dela", 4) == 0)
		op = OP_DELA;

	if (op == OP_INLD)
		return -EINVAL;

	/**
	 * Create entry in name list for add opeartions.
	 */
	if (op == OP_ADDF || op == OP_ADDE) {
		// Alloc memory for list element
		elem = kmalloc(sizeof(struct _list), GFP_KERNEL);
		if (!elem)
			return -ENOMEM;

		elem->name = kmalloc(local_buffer_size - 5, GFP_KERNEL);
		if (!elem->name) {
			kfree(elem);
			return -ENOMEM;
		}

		// Copy name and set NULL
		memcpy(elem->name, local_buffer + BUF_MIN_SIZE, local_buffer_size -
				BUF_MIN_SIZE);
		elem->name[local_buffer_size - BUF_MIN_SIZE - 1] = '\0';
	}

	switch (op) {
	case OP_ADDF:
		list_add(&elem->list, &name_list);
		break;
	case OP_ADDE:
		list_add_tail(&elem->list, &name_list);
		break;
	case OP_DELF:
		list_for_each_safe(_it, tmp, &name_list) {
			elem = list_entry(_it, struct _list, list);
			if (memcmp(elem->name, local_buffer + BUF_MIN_SIZE,
						strlen(elem->name)) == 0) {
				list_del(_it);
				kfree(elem->name);
				kfree(elem);
				return local_buffer_size;
			}
		}
		break;
	case OP_DELA:
		list_for_each_safe(_it, tmp, &name_list) {
			elem = list_entry(_it, struct _list, list);
			if (memcmp(elem->name, local_buffer + BUF_MIN_SIZE,
						strlen(elem->name)) == 0) {
				list_del(_it);
				kfree(elem->name);
				kfree(elem);
			}
		}
		break;
	default:
		break;
	}

	return local_buffer_size;
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

/**
 * Tracer device file operations.
 */
static const struct file_operations tracer_fops = {
	.owner	= THIS_MODULE,
};

/**
 * Tracer miscdevice structure.
 */
static const struct miscdevice tracer_misc_dev = {
	.minor	= TRACER_DEV_MINOR,
	.name	= TRACER_DEV_NAME,
	.fops	= tracer_fops
};

static int tracer_init(void)
{
	int ret = 0;

	// Register tracer miscdevice
	ret = misc_register(&tracer_misc_dev);
	if (ret) {
		printk(KERN_ERR "Unable to register miscdevice!\n");
		return ret;
	}

	printk(KERN_INFO "Register successfully!\n");

	return ret;
}

static void tracer_exit(void)
{
	// Unregister tracer miscdevice
	misc_deregister(&tracer_misc_dev);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Tracer");
MODULE_LICENSE("GPL v2");
