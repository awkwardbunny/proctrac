#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brian Hong");
MODULE_DESCRIPTION("Process File Access Tracker Kernel Module");
MODULE_VERSION("0.1");

typedef struct st_fcontrl fcontrl;
typedef struct st_fcontrl {
	char fn[32];
	int access;
	fcontrl *next;
} fcontrl;
fcontrl *flist;

static ssize_t filelist_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
	fcontrl *fcp = flist;
	int r = 0;
	int sum = 0;
	while(fcp){
		//printk(KERN_INFO "PTRAC: %d %s\n", fcp->access, fcp->fn);
		r = sprintf(buf+sum, "%d %s\n", fcp->access, fcp->fn);
		sum += r;
		fcp = fcp->next;
	}
	return sum;
}

static ssize_t filelist_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count){
	fcontrl *f;
	fcontrl *fcp = flist;
	fcontrl *prev = NULL;
	char fn[32];
	int access = 0;
	fcontrl *exists = NULL;

	printk(KERN_INFO "PTRAC: Adding to filelist: %s", buf);
	sscanf(buf, "%31s %d", fn, &access);

	// Search if exists
	while(fcp){
		if(!strcmp(fn, fcp->fn)){
			printk("File exists! ");
			exists = fcp;
			break;
		}
		prev = fcp;
		fcp = fcp->next;
	}

	if(exists){
		if(access){
			//Update
			exists->access = access;
			printk("Updated access\n");
		}else{
			//Remove element
			if(flist == exists){
				flist = exists->next;
			}else{
				prev->next = exists->next;
			}
			kfree(exists);
			printk("Removed file\n");
		}
	}else if(access){
		// Create new fcontrl
		f = (fcontrl *)kmalloc(sizeof(fcontrl), __GFP_FS);
		strcpy(f->fn, fn);
		f->access = access;
	
		// Add to list
		f->next = flist;
		flist = f;
	}
	return count;
}

struct kobj_attribute kattr = __ATTR_RW(filelist);
struct kobject *kobj_ref;

static int __init ptrac_init(void){

	printk(KERN_INFO "PTRAC: Module loaded!\n");

	// Setup sysfs
	// Create new kobject and register /sys/ptrac
	kobj_ref = kobject_create_and_add("ptrac", NULL);
	//printk(KERN_INFO "PTRAC: 0x%x\n", (int)kobj_ref);

	// Initialize filelist
	flist = NULL;
	
	// Create /sys/ptrac/filelist
	if(sysfs_create_file(kobj_ref, &kattr.attr)){
		printk(KERN_INFO "Cannot create sysfs file...\n");
		return -1;
	}

	return 0;
}

static void __exit ptrac_exit(void){

	// Decrement reference counter for /sys/ptrac
	kobject_put(kobj_ref);
	// Remove /sys/ptrac/filelist
	sysfs_remove_file(kernel_kobj, &kattr.attr);

	while(flist){
		fcontrl *fcp = flist->next;
		kfree(flist);
		flist = fcp;
	}

	printk(KERN_INFO "PTRAC: Module unloaded!\n");
}

module_init(ptrac_init);
module_exit(ptrac_exit);
