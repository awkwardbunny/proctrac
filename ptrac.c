#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <asm/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brian Hong");
MODULE_DESCRIPTION("Process File Access Tracker Kernel Module");
MODULE_VERSION("0.1");

typedef struct st_fcontrl {
	char fn[32];
	int access;
} fcontrol;
fcontrol flist[32];

static int __init ptrac_init(void){
	printk(KERN_INFO "PTRAC: Module loaded!\n");

	return 0;
}

static void __exit ptrac_exit(void){
	printk(KERN_INFO "PTRAC: Module unloaded!\n");
}

module_init(ptrac_init);
module_exit(ptrac_exit);
