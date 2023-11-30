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
#include <linux/miscdevice.h>

#include "tracer.h"
#include "tracer_info.h"

/*********************** TRACER PROC FILE OPERATIONS **************************/

static int tracer_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, tracer_info_show, NULL);
}

/************************ TRACER DEV FILE OPERATIONS **************************/

/**
 * Tracer unlocked_ioctl function. This is responsible for adding or removing
 * a process to/from the list.
 *
 * @cmd	: Command for add or remove a process.
 * @arg	: Process pid.
 */
static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TRACER_ADD_PROCESS:
		return tracer_info_add_entry(arg);
	case TRACER_REMOVE_PROCESS:
		return tracer_info_delete_entry(arg);
	default:
		return -ENOTTY;
	}

	return 0;
}

/***************************** TRACER INIT/EXIT ******************************/

struct proc_dir_entry *proc_tracer_read;

/**
 * Tracer proc file operations.
 */
static const struct proc_ops tracer_read_pops = {
	.proc_open		= tracer_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

/**
 * Tracer device file operations.
 */
static const struct file_operations tracer_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl	= tracer_ioctl
};

/**
 * Tracer miscdevice structure.
 */
static struct miscdevice tracer_misc_dev = {
	.minor			= TRACER_DEV_MINOR,
	.name			= TRACER_DEV_NAME,
	.fops			= &tracer_fops
};

static int tracer_init(void)
{
	int ret = 0;

	// Register tracer miscdevice
	ret = misc_register(&tracer_misc_dev);
	if (ret) {
		pr_err("Miscdevice register failed!\n");
		//goto tracer_info_deinit;
		goto err;
	}

	// Register tracer proc entry
	proc_tracer_read = proc_create(TRACER_DEV_NAME, 0000, NULL,
						&tracer_read_pops);
	if (!proc_tracer_read) {
		pr_err("Proc create failed!\n");
		ret = -ENOMEM;
		goto misc_deregister;
	}

	// Initialize tracer info
	ret = tracer_info_init();
	if (ret) {
		pr_err("Tracer info initialization failed!\n");
		goto proc_remove;
	}

	return 0;

proc_remove:
	proc_remove(proc_tracer_read);

misc_deregister:
	misc_deregister(&tracer_misc_dev);

err:
	return ret;
}

static void tracer_exit(void)
{
	// Unregister tracer miscdevice
	misc_deregister(&tracer_misc_dev);

	// Unregister tracer proc entry
	proc_remove(proc_tracer_read);

	// Unregister probes
	tracer_info_deinit();
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Tracer");
MODULE_LICENSE("GPL v2");
