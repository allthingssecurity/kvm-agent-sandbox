// SPDX-License-Identifier: GPL-2.0
/* hello.c: a tiny character device, /dev/hello. */
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include "hello_ioctl.h"

#define MSG_MAX 64

static DEFINE_MUTEX(lock);	/* two programs may use us at once */
static char message[MSG_MAX] = "nothing yet";
static int count;

static ssize_t hello_read(struct file *f, char __user *buf,
			  size_t len, loff_t *pos)
{
	char out[128];
	int n;

	mutex_lock(&lock);
	n = scnprintf(out, sizeof(out),
		      "Hello from the kernel. Last message: %s\n", message);
	if (*pos == 0)
		count++;
	mutex_unlock(&lock);

	if (*pos >= n)
		return 0;			/* end of file */
	if (len > n - *pos)
		len = n - *pos;
	/* buf is a user address: never touch it directly. */
	if (copy_to_user(buf, out + *pos, len))
		return -EFAULT;
	*pos += len;
	return len;
}

static ssize_t hello_write(struct file *f, const char __user *buf,
			   size_t len, loff_t *pos)
{
	char tmp[MSG_MAX];

	if (len >= MSG_MAX)
		len = MSG_MAX - 1;		/* keep it bounded */
	if (copy_from_user(tmp, buf, len))
		return -EFAULT;
	tmp[len] = '\0';
	if (len && tmp[len - 1] == '\n')
		tmp[len - 1] = '\0';

	mutex_lock(&lock);
	strscpy(message, tmp, sizeof(message));
	mutex_unlock(&lock);
	pr_info("hello: stored \"%s\"\n", tmp);
	return len;
}

static long hello_ioctl(struct file *f, unsigned int cmd,
			unsigned long arg)
{
	int value;

	switch (cmd) {
	case HELLO_GET_COUNT:
		mutex_lock(&lock);
		value = count;
		mutex_unlock(&lock);
		if (copy_to_user((int __user *)arg, &value, sizeof(value)))
			return -EFAULT;
		return 0;
	case HELLO_RESET:
		mutex_lock(&lock);
		count = 0;
		mutex_unlock(&lock);
		pr_info("hello: counter reset\n");
		return 0;
	default:
		return -ENOTTY;		/* "not a command I know" */
	}
}

static const struct file_operations hello_fops = {
	.owner		= THIS_MODULE,
	.read		= hello_read,
	.write		= hello_write,
	.unlocked_ioctl	= hello_ioctl,
};

static struct miscdevice hello_dev = {
	.minor	= MISC_DYNAMIC_MINOR,	/* let the kernel pick */
	.name	= "hello",		/* becomes /dev/hello */
	.fops	= &hello_fops,
	.mode	= 0666,			/* any user may open it */
};

static int __init hello_init(void)
{
	int err = misc_register(&hello_dev);

	if (err)
		return err;
	pr_info("hello: ready as /dev/hello, minor %d\n", hello_dev.minor);
	return 0;
}

static void __exit hello_exit(void)
{
	misc_deregister(&hello_dev);
	pr_info("hello: goodbye\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A tiny misc device for the handbook");
