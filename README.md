# Assignments
 Repository serves as a centralized hub for organizing and managing various assignments.

 ## Memory Allocator
Mini [memory allocator](https://gitlab.cs.pub.ro/operating-systems/assignment-memory-allocator) supporting malloc/calloc/realloc/free implemented with [brk](https://man7.org/linux/man-pages/man2/brk.2.html) and [mmap](https://man7.org/linux/man-pages/man2/mmap.2.html) system calls.
 

 ## Kernel List API
[Kernel module](https://linux-kernel-labs.github.io/refs/heads/master/so2/assign0-kernel-api.html) which stores data in an internal list using list API implemented in kernel.


 ## Kernel Kprobe Tracer
Surveillant [kernel module](https://linux-kernel-labs.github.io/refs/heads/master/so2/assign1-kprobe-based-tracer.html) aiming to intercept the the following calls:
```
kmalloc/kfree
schedule
up/down_interruptible
mutex_lock/mutex_unlock
```


 ## Kernel UART Driver
 [Kernel module](https://linux-kernel-labs.github.io/refs/heads/master/so2/assign2-driver-uart.html) that implements a driver for the serial port (UART16550).
