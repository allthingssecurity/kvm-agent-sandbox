/* hello_ioctl.h: the contract between the driver and user programs. */
#ifndef HELLO_IOCTL_H
#define HELLO_IOCTL_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif

#define HELLO_MAGIC 'h'	/* one letter that tags our commands */

/* Read the number of greetings served so far into an int. */
#define HELLO_GET_COUNT _IOR(HELLO_MAGIC, 1, int)
/* Set the counter back to zero. No argument. */
#define HELLO_RESET     _IO(HELLO_MAGIC, 2)

#endif
