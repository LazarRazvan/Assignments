/*
 * Uart16550 defines header file
 */

#ifndef DEFINES_H__
#define DEFINES_H__ 1

#include <asm/io.h>

/**
 * Uart16550 module name.
 */
#define MODULE_NAME			"uart16550"

/**
 * Com1
 */
#define COM1_ADDR			0x3F8
#define COM1_NR_PORTS		8
#define COM1_IRQ			4

/**
 * Com2
 */
#define COM2_ADDR			0x2F8
#define COM2_NR_PORTS		8
#define COM2_IRQ			3

// Divisor Latch Access Bit
#define LCR_DLAB			0x80

/**
 * Line control register
 */
static inline void LCR_write(int addr, char val)
{
	outb(addr + 3, val);
}

static inline char LCR_read(int addr)
{
	return inb(addr + 3);
}

/**
 * Divisor latch high.
 */
static inline void DLH_write(int addr, char val)
{
	outb(addr + 1, val);
}

static inline char DLH_read(int addr)
{
	return inb(addr + 1);
}

/**
 * Divisor latch low.
 */
static inline void DLL_write(int addr, char val)
{
	outb(addr + 0, val);
}

static inline char DLL_read(int addr)
{
	return inb(addr + 0);
}

#endif /* DEFINES_H_ */
