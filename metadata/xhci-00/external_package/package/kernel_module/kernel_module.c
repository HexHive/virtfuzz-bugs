#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int myinit(void)
{
    printk(KERN_INFO "hello init\n");
    return 0;
}

static void myexit(void)
{
    printk(KERN_INFO "hello exit\n");
}

module_init(myinit)
module_exit(myexit)
