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
#include <linux/rwlock.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>

#include "tracer_info.h"


/*************************** TRACER INFO GLOBALS ******************************/

// Tracer number of probes
#define PROBES_NUM					8

// List to tracer monitored processes
static struct list_head tracer_info_list;

// List spinlock synchronization (used with rcu)
static spinlock_t tracer_lock;

/************************** TRACER INFO STRUCTURES ****************************/

/**
 * Data structure to track memory information for each process.
 */

struct tracer_mem_info {
	void					*addr;			// allocated mem address
	size_t					size;			// allocated mem size
	struct list_head		_node;			// node for process mem list
};

/**
 * Data structure to track kretprobes information for each process.
 */

struct tracer_proc_info {
	pid_t					_pid;			// process pid
	uint32_t				_kmalloc;		// number of kmalloc
	uint32_t				_kmalloc_mem;	// mem size allocated using kmalloc
	uint32_t				_kfree;			// number of kfree
	uint32_t				_kfree_mem;		// mem size freed using kfree
	uint32_t				_up;			// number of up
	uint32_t				_down;			// number of down
	uint32_t				_mlock;			// number of mutex lock
	uint32_t				_munlock;		// number of mutext unlock
	uint32_t				_sched;			// number of schedule
	struct list_head		_mem_list;		// process mem list
	struct list_head		_node;			// node for processes list
};


/**************************** TRACER INFO STATIC ******************************/

/**
 * Get process entry from tracer_info_list based on pid.
 */
static inline struct tracer_proc_info *__get_proc_entry(pid_t pid)
{
	struct tracer_proc_info *elem;

	list_for_each_entry_rcu(elem, &tracer_info_list, _node) {
		if (elem->_pid == pid)
			return elem;
	}

	return NULL;
}

/**
 * Create tracer process entry for the list of monitored processes.
 * Should not be called in critical section since GFP_KERNEL is used and
 * might sleep.
 */
static struct tracer_proc_info *__create_proc_entry(pid_t pid)
{
	struct tracer_proc_info *ptr = NULL;

	// Alloc memory for new process entry
	ptr = kmalloc(sizeof(struct tracer_proc_info), GFP_KERNEL);
	if (!ptr)
		return NULL;

	memset(ptr, 0, sizeof(struct tracer_proc_info));

	// Initialize list for process memory and pid
	ptr->_pid = pid;
	INIT_LIST_HEAD(&ptr->_mem_list);

	return ptr;
}


/**
 * Create tracer mem entry for a monitored process.
 */
static struct tracer_mem_info *__create_mem_entry(void *addr, size_t size)
{
	struct tracer_mem_info *ptr = NULL;

	// Alloc memory for new memory entry
	ptr = kmalloc(sizeof(struct tracer_mem_info), GFP_ATOMIC);
	if (!ptr)
		return NULL;

	memset(ptr, 0, sizeof(struct tracer_mem_info));

	// Set data
	ptr->addr = addr;
	ptr->size = size;

	return ptr;
}

/**
 * Destroy tracer mem entry for a monitored process.
 */
static void __destroy_proc_mem(struct tracer_proc_info *ptr)
{
	struct tracer_mem_info *elem;
	struct list_head *_it, *_tmp;

	list_for_each_safe(_it, _tmp, &ptr->_mem_list) {
		elem = list_entry(_it, struct tracer_mem_info, _node);
		list_del(_it);
		kfree(elem);
	}
}

/**
 * Destroy tracer process memory entry for the list of monitored processes.
 */
static int __destroy_proc_entry(pid_t pid)
{
	struct tracer_proc_info *elem;

	rcu_read_lock();

	list_for_each_entry_rcu(elem, &tracer_info_list, _node) {
		if (elem->_pid == pid) {
			rcu_read_unlock();

			// Delete element under tracer spinlock
			spin_lock(&tracer_lock);
			list_del_rcu(&elem->_node);
			spin_unlock(&tracer_lock);

			// Release memory
			__destroy_proc_mem(elem);
			kfree(elem);

			return 0;
		}
	}

	rcu_read_unlock();
	return -EINVAL;
}

/**
 * Destroy all monitored processes by tracer.
 */
static void __destroy_proc_entries(void)
{
	struct list_head *_it, *_tmp;
	struct tracer_proc_info *elem;

	list_for_each_safe(_it, _tmp, &tracer_info_list) {
		elem = list_entry(_it, struct tracer_proc_info, _node);
		list_del(_it);
		__destroy_proc_mem(elem);
		kfree(elem);
	}
}

/********************* TRACER INFO PROBES IMPLEMENTATION **********************/

/**
 * __kmalloc entry kretprobe handler.
 */
static int tracer_probe_kmalloc_entry_handler(struct kretprobe_instance *ri,
											struct pt_regs *regs)
{
	// Move to kretprobe instance extra space
	size_t *size_ptr = (size_t *)ri->data;

	// Store __kmalloc size from return value
	*size_ptr = (size_t)regs_return_value(regs);

	return 0;
}

/**
 * __kmalloc kretprobe handler.
 */
static int tracer_probe_kmalloc_handler(struct kretprobe_instance *ri,
										struct pt_regs *regs)
{
	void *addr;
	size_t size;
	struct tracer_mem_info *mem;
	struct tracer_proc_info *ptr;

	// Extract __kmalloc size and address from return value
	size = *((size_t *)ri->data);
	addr = (void *)regs_return_value(regs);

	rcu_read_lock();

	// Get monitored process
	ptr = __get_proc_entry(current->pid);
	if (!ptr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	// Create memory entry
	mem = __create_mem_entry(addr, size);
	if (!mem) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	// Add memory entry to process
	list_add_tail_rcu(&mem->_node, &ptr->_mem_list);

	ptr->_kmalloc++;
	ptr->_kmalloc_mem += size;

	rcu_read_unlock();
	return 0;
}

/**
 * kfree kretprobe handler.
 */
static int tracer_probe_kfree_handler(struct kretprobe_instance *ri,
										struct pt_regs *regs)
{
	void *addr;
	struct tracer_mem_info *mem;
	struct tracer_proc_info *ptr;

	// Extract kfree address from return value
	addr = (void *)regs_return_value(regs);

	rcu_read_lock();

	// Get monitored process
	ptr = __get_proc_entry(current->pid);
	if (!ptr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	// Update kfree info for address and remove mem entry
	list_for_each_entry_rcu(mem, &ptr->_mem_list, _node) {
		if (mem->addr == addr) {
			ptr->_kfree++;
			ptr->_kfree_mem += mem->size;

			rcu_read_unlock();

			// Delete memory entry from list under tracer spinlock
			spin_lock(&tracer_lock);
			list_del_rcu(&mem->_node);
			spin_unlock(&tracer_lock);

			// Free memory entry space
			kfree(mem);

			return 0;
		}
	}

	rcu_read_unlock();
	return -EINVAL;
}

/**
 * schedule kretprobe handler.
 */
static int tracer_probe_schedule_handler(struct kretprobe_instance *ri,
										struct pt_regs *regs)
{
	struct tracer_proc_info *ptr;

	rcu_read_lock();

	ptr = __get_proc_entry(current->pid);
	if (!ptr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	ptr->_sched++;

	rcu_read_unlock();
	return 0;
}

/**
 * up kretprobe handler.
 */
static int tracer_probe_up_handler(struct kretprobe_instance *ri,
									struct pt_regs *regs)
{
	struct tracer_proc_info *ptr;

	rcu_read_lock();

	ptr = __get_proc_entry(current->pid);
	if (!ptr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	ptr->_up++;

	rcu_read_unlock();
	return 0;
}

/**
 * down kretprobe handler.
 */
static int tracer_probe_down_handler(struct kretprobe_instance *ri,
										struct pt_regs *regs)
{
	struct tracer_proc_info *ptr;

	rcu_read_lock();

	ptr = __get_proc_entry(current->pid);
	if (!ptr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	ptr->_down++;

	rcu_read_unlock();
	return 0;
}

/**
 * mutex_lock kretprobe handler.
 */
static int tracer_probe_mlock_handler(struct kretprobe_instance *ri,
										struct pt_regs *regs)
{
	struct tracer_proc_info *ptr;

	rcu_read_lock();

	ptr = __get_proc_entry(current->pid);
	if (!ptr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	ptr->_mlock++;

	rcu_read_unlock();
	return 0;
}


/**
 * mutex_unlock kretprobe handler.
 */
static int tracer_probe_munlock_handler(struct kretprobe_instance *ri,
										struct pt_regs *regs)
{
	struct tracer_proc_info *ptr;

	rcu_read_lock();

	ptr = __get_proc_entry(current->pid);
	if (!ptr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	ptr->_munlock++;

	rcu_read_unlock();
	return 0;
}

/**
 * do_exit kreptrobe handler.
 * This remove current process from traced list.
 */
static int tracer_probe_do_exit_handler(struct kretprobe_instance *ri,
										struct pt_regs *regs)
{
	return __destroy_proc_entry(current->pid);
}

/*************************** TRACER INFO ENTRIES ******************************/

/**
 * Add process entry to tracer info list.
 */
int tracer_info_add_entry(pid_t pid)
{
	struct tracer_proc_info *ptr = __create_proc_entry(pid);

	if (!ptr)
		return -ENOMEM;

	// Add new process in rcu protected lock
	rcu_read_lock();
	list_add_tail_rcu(&ptr->_node, &tracer_info_list);
	rcu_read_unlock();

	return 0;
}

/**
 * Delete process entry from tracer info list.
 */
int tracer_info_delete_entry(pid_t pid)
{
	return __destroy_proc_entry(pid);
}

/************************ TRACER INFO PROBES STRUCTURE ************************/

static struct kretprobe tracer_probes[PROBES_NUM] = {
	// __kmalloc
	{
		.kp.symbol_name	= "__kmalloc",
		.entry_handler	= tracer_probe_kmalloc_entry_handler,
		.handler		= tracer_probe_kmalloc_handler,
		.data_size		= sizeof(size_t),	// size extra space
		.maxactive		= 32
	},
	// kfree
	{
		.kp.symbol_name	= "kfree",
		.entry_handler	= tracer_probe_kfree_handler,
		.maxactive		= 32
	},
	// schedule
	{
		.kp.symbol_name	= "schedule",
		.entry_handler	= tracer_probe_schedule_handler,
		.maxactive		= 32
	},
	// up
	{
		.kp.symbol_name	= "up",
		.entry_handler	= tracer_probe_up_handler,
		.maxactive		= 32
	},
	// down_interruptible
	{
		.kp.symbol_name	= "down_interruptible",
		.entry_handler	= tracer_probe_down_handler,
		.maxactive		= 32
	},
	// mutex_lock_nested
	{
		.kp.symbol_name	= "mutex_lock_nested",
		.entry_handler	= tracer_probe_mlock_handler,
		.maxactive		= 32
	},
	// mutex_unlock
	{
		.kp.symbol_name	= "mutex_unlock",
		.entry_handler	= tracer_probe_munlock_handler,
		.maxactive		= 32
	},
	// do_exit
	{
		.kp.symbol_name	= "do_exit",
		.entry_handler	= tracer_probe_do_exit_handler,
		.maxactive		= 32
	}
};

/************************** TRACER INFO INIT/DEINIT ***************************/

// Tracer proc header print format
#define TRACER_PROC_HEADER_FMT	\
	"%-13s%-13s%-13s%-13s%-13s%-13s%-13s%-13s%-13s%-13s\n"

// Tracer proc data print format
#define TRACER_PROC_DATA_FMT	\
	"%-13u%-13u%-13u%-13u%-13u%-13u%-13u%-13u%-13u%-13u\n"

/**
 * Tracer proc read function. This is responsible for displaying information
 * for all registered processes.
 */
int tracer_info_show(struct seq_file *m, void *v)
{
	struct list_head *_it;
	struct tracer_proc_info *elem;

	seq_printf(m, TRACER_PROC_HEADER_FMT, "PID", "kmalloc", "kfree",
	"kmalloc_mem", "kfree_mem", "sched", "up", "down", "lock", "unlock");

	rcu_read_lock();

	list_for_each(_it, &tracer_info_list) {
		elem = list_entry(_it, struct tracer_proc_info, _node);

		seq_printf(m, TRACER_PROC_DATA_FMT, elem->_pid, elem->_kmalloc,
					elem->_kfree, elem->_kmalloc_mem, elem->_kfree_mem,
					elem->_sched, elem->_up, elem->_down, elem->_mlock,
					elem->_munlock);
	}

	rcu_read_unlock();

	return 0;
}

/************************** TRACER INFO INIT/DEINIT ***************************/

/**
 * Initialize tracer info.
 */
int tracer_info_init(void)
{
	int id;
	int ret = 0;

	// Processes list init
	INIT_LIST_HEAD(&tracer_info_list);

	// Processes read-write lock init
	spin_lock_init(&tracer_lock);

	// Kretprobes register
	for (id = 0; id < PROBES_NUM; id++) {
		ret = register_kretprobe(&tracer_probes[id]);
		if (ret < 0)
			goto unregister_probes;
	}

	return ret;

unregister_probes:
	for (; id >= 0; id--)
		unregister_kretprobe(&tracer_probes[id]);

	return ret;
}

/**
 * Deinitialize tracer info.
 */
void tracer_info_deinit(void)
{
	int id;

	// Unregister kfretprobes
	for (id = 0; id < PROBES_NUM; id++)
		unregister_kretprobe(&tracer_probes[id]);

	// Destroy tracer list
	__destroy_proc_entries();
}

MODULE_DESCRIPTION("Tracer");
MODULE_LICENSE("GPL v2");
