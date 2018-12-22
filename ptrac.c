#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brian Hong");
MODULE_DESCRIPTION("Process File Access Tracker Kernel Module");
MODULE_VERSION("0.1");

typedef struct st_fcontrl {
	char fn[32];
	int access;
} fcontrol;
fcontrol flist[32];

static ssize_t filelist_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
	return sprintf(buf, "%s", "hello");
}

static ssize_t filelist_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
	printk("%s\n", buf);
	return count;
}

struct kobj_attribute kattr = __ATTR_RW(filelist);
struct kobject *kobj_ref;

static int __init ptrac_init(void){

	printk(KERN_INFO "PTRAC: Module loaded!\n");
	kobj_ref = kobject_create_and_add("ptrac", NULL);
	printk(KERN_INFO "PTRAC: 0x%x\n", (int)kobj_ref);
	
	if(sysfs_create_file(kobj_ref, &kattr.attr)){
		printk(KERN_INFO "Cannot create sysfs file...\n");
		return -1;
	}

	return 0;
}

static void __exit ptrac_exit(void){
	kobject_put(kobj_ref);
	sysfs_remove_file(kernel_kobj, &kattr.attr);
	printk(KERN_INFO "PTRAC: Module unloaded!\n");
}

module_init(ptrac_init);
module_exit(ptrac_exit);
