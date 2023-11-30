// SPDX-License-Identifier: GPL-2.0+

/*
 * uart16550.c - Uart16550 serial port driver
 */

#include "defines.h"
#include "uart16550.h"

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/fs.h>

/**
 * Uart16550 parameters.
 */
// Major
int major = 42;
module_param(major, int, 0);
MODULE_PARM_DESC(major, "Uart16550 serial port driver major");

// Option
int option = OPTION_BOTH;
module_param(option, int, 0);
MODULE_PARM_DESC(option, "Uart16500 serial port driver option");

/**
 * Uart16550 character device structure.
 */
struct uart16550 {
    struct cdev cdev;
};
struct uart16550 uart16550_devs[2];

/**
 * Uart16550 file operations.
 */
static int uart16550_open(struct inode *inode, struct file *file)
{
	struct uart16550 *data;

    data = container_of(inode->i_cdev, struct uart16550, cdev);

    file->private_data = data;

	return 0;
}

static int uart16550_read(struct file *file, char __user *user_buffer,
							size_t size, loff_t *offset)
{
	return 0;
}

static int uart16550_write(struct file *file, const char __user *user_buffer,
							size_t size, loff_t * offset)
{
	return 0;
}

static long uart16550_ioctl(struct file *file, unsigned int cmd,
							unsigned long arg)
{
	char lcr;
	int port_addr;
	struct uart16550_line_info cfg;
	struct uart16550 *uart16550_dev;

	uart16550_dev = (struct uart16550 *)file->private_data;
	if (!uart16550_dev)
		return -EINVAL;

	// Get port address
	port_addr = uart16550_dev == &uart16550_devs[0] ? COM1_ADDR : COM2_ADDR;

	// Read data from user
	if (copy_from_user(&cfg, (void *)arg, sizeof(struct uart16550_line_info)))
		return -EFAULT;

	if (cmd != UART16550_IOCTL_SET_LINE)
		return -EINVAL;

	// Enable DLAB; set baud; disable DLAB
	lcr = LCR_read(port_addr);

	lcr |= LCR_DLAB;
	LCR_write(port_addr, lcr);

	DLH_write(port_addr, (char)((cfg.baud >> 8) & 0xFF));
	DLH_write(port_addr, (char)((cfg.baud & 0xFF)));

	//lcr &= ~LCR_DLAB;
	//LCR_write(port_addr, lcr);

	// Set line control: data bits, stop bits and parity
	lcr = cfg.len | cfg.par | cfg.stop;
	LCR_write(port_addr, lcr);

	return 0;
}

const struct file_operations uart16550_fops = {
    .owner			= THIS_MODULE,
    .open			= uart16550_open,
    .read			= uart16550_read,
    .write			= uart16550_write,
    .unlocked_ioctl	= uart16550_ioctl
};

/**
 * Uart16550 interrupt handler.
 */
irqreturn_t uart16550_irq_handler(int irq_no, void *dev_id)
{
	return IRQ_HANDLED;
}

/*
 * Uart16550 init.
 */
static int uart16550_init(void)
{
	int rv;

	if (option == OPTION_COM1) {
		// Register device
		rv = register_chrdev_region(MKDEV(major, 0), 1, MODULE_NAME);
		if (rv)
			return rv;

		// I/O ports
		if (!request_region(COM1_ADDR, COM1_NR_PORTS, MODULE_NAME)) {
			unregister_chrdev_region(MKDEV(major, 0), 1);
			return -ENODEV;
		}

		// Request interrupt
		rv = request_irq(COM1_IRQ, uart16550_irq_handler, IRQF_SHARED,
						MODULE_NAME, &uart16550_devs[0]);
		if (rv < 0) {
			release_region(COM1_ADDR, COM1_NR_PORTS);
			unregister_chrdev_region(MKDEV(major, 0), 1);
			return rv;
		}
		cdev_init(&uart16550_devs[0].cdev, &uart16550_fops);
		cdev_add(&uart16550_devs[0].cdev, MKDEV(major, 0), 1);

		return 0;
	} else if (option == OPTION_COM2) {
		// Register device
		rv = register_chrdev_region(MKDEV(major, 1), 1, MODULE_NAME);
		if (rv)
			return rv;

		// I/O ports
		if (!request_region(COM2_ADDR, COM2_NR_PORTS, MODULE_NAME)) {
			unregister_chrdev_region(MKDEV(major, 1), 1);
			return -ENODEV;
		}

		// Request interrupt
		rv = request_irq(COM2_IRQ, uart16550_irq_handler, IRQF_SHARED,
						MODULE_NAME, &uart16550_devs[1]);
		if (rv < 0) {
			release_region(COM2_ADDR, COM2_NR_PORTS);
			unregister_chrdev_region(MKDEV(major, 0), 1);
			return rv;
		}
		cdev_init(&uart16550_devs[1].cdev, &uart16550_fops);
		cdev_add(&uart16550_devs[1].cdev, MKDEV(major, 1), 1);

		return 0;

	} else if (option == OPTION_BOTH) {
		// Register device
		rv = register_chrdev_region(MKDEV(major, 0), 2, MODULE_NAME);
		if (rv)
			return rv;

		// I/O ports
		if (!request_region(COM1_ADDR, COM1_NR_PORTS, MODULE_NAME)) {
			unregister_chrdev_region(MKDEV(major, 0), 2);
			return -ENODEV;
		}
		if (!request_region(COM2_ADDR, COM2_NR_PORTS, MODULE_NAME)) {
			release_region(COM1_ADDR, COM1_NR_PORTS);
			unregister_chrdev_region(MKDEV(major, 0), 2);
			return -ENODEV;
		}

		// Request interrupt
		rv = request_irq(COM1_IRQ, uart16550_irq_handler, IRQF_SHARED,
						MODULE_NAME, &uart16550_devs[0]);
		if (rv < 0) {
			release_region(COM2_ADDR, COM2_NR_PORTS);
			release_region(COM1_ADDR, COM1_NR_PORTS);
			unregister_chrdev_region(MKDEV(major, 0), 2);
			return rv;
		}
		rv = request_irq(COM2_IRQ, uart16550_irq_handler, IRQF_SHARED,
						MODULE_NAME, &uart16550_devs[1]);
		if (rv < 0) {
			free_irq(COM1_IRQ, &uart16550_devs[0]);
			release_region(COM2_ADDR, COM2_NR_PORTS);
			release_region(COM1_ADDR, COM1_NR_PORTS);
			unregister_chrdev_region(MKDEV(major, 0), 2);
			return rv;
		}

		cdev_init(&uart16550_devs[0].cdev, &uart16550_fops);
		cdev_add(&uart16550_devs[0].cdev, MKDEV(major, 0), 1);

		cdev_init(&uart16550_devs[1].cdev, &uart16550_fops);
		cdev_add(&uart16550_devs[1].cdev, MKDEV(major, 1), 1);

		return 0;
	}

	// Invalid option value.
	printk(KERN_ERR "Option value %d error!\n", option);

	return -EINVAL;
}


/*
 * Uart16550 exit.
 */
static void uart16550_exit(void)
{
	if (option == OPTION_COM1) {
		cdev_del(&uart16550_devs[0].cdev);
		free_irq(COM1_IRQ, &uart16550_devs[0]);
		release_region(COM1_ADDR, COM1_NR_PORTS);
		unregister_chrdev_region(MKDEV(major, 0), 1);

		return;
	} else if (option == OPTION_COM2) {
		cdev_del(&uart16550_devs[1].cdev);
		free_irq(COM2_IRQ, &uart16550_devs[1]);
		release_region(COM2_ADDR, COM2_NR_PORTS);
		unregister_chrdev_region(MKDEV(major, 1), 1);

		return;
	} else if (option == OPTION_BOTH) {
		cdev_del(&uart16550_devs[0].cdev);
		cdev_del(&uart16550_devs[1].cdev);
		free_irq(COM1_IRQ, &uart16550_devs[0]);
		free_irq(COM2_IRQ, &uart16550_devs[1]);
		release_region(COM1_ADDR, COM1_NR_PORTS);
		release_region(COM2_ADDR, COM2_NR_PORTS);
		unregister_chrdev_region(MKDEV(major, 0), 2);

		return;
	}
}

module_init(uart16550_init);
module_exit(uart16550_exit);

MODULE_DESCRIPTION("Uart16550 Driver");
MODULE_LICENSE("GPL v2");
