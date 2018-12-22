#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>

#define HOOK(_name, _function, _original) \
	{ \
		.name = (_name), \
		.function = (_function), \
		.original = (_original) \
	}

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brian Hong");
MODULE_DESCRIPTION("Process File Access Tracker Kernel Module");
MODULE_VERSION("0.1");

typedef struct st_fcontrl fcontrl;
typedef struct st_fcontrl {
	char fn[512];
	int access;
	fcontrl *next;
} fcontrl;
fcontrl *flist;

static char *dup_fn(const char __user *filename){
	char *kfn;
	kfn = kmalloc(512, GFP_KERNEL);
	if(!kfn)
		return NULL;
	if(strncpy_from_user(kfn, filename, 512) < 0){
		kfree(kfn);
		return NULL;
	}
	return kfn;

}

static asmlinkage long (*real_sys_open)(const char __user *filename, int flags, umode_t mode);
static asmlinkage long fh_sys_open(const char __user *filename, int flags, umode_t mode){
	long ret;
	fcontrl *fcp = flist;

	//printk("%s\n", filename);
	//pr_debug("open() %p\n", filename);
	//pr_debug("open() %c%c%c%c%c%c\n", filename[0], filename[1], filename[2], filename[3], filename[4]);
	char *kfn = dup_fn(filename);
	//int pid = task_pid_nr(current);
	//pr_debug("PTRAC: %d is opening %s\n", pid, kfn);
	
	while(fcp){
		if(!strcmp(fcp->fn, kfn)){
			printk(KERN_INFO "PTRAC: PID %d is opening %s in mode %o with following flags:\n", task_pid_nr(current), kfn, mode);
			if(flags & O_APPEND)
				printk("O_APPEND ");
			if(flags & O_CLOEXEC)
				printk("O_CLOEXEC ");
			if(flags & O_CREAT)
				printk("O_CREAT ");
			if(flags & O_TRUNC)
				printk("O_TRUNC ");
			if(flags & O_RDONLY)
				printk("O_RDONLY ");
			if(flags & O_WRONLY)
				printk("O_WRONLY ");
			if(flags & O_RDWR)
				printk("O_RDWR ");
			break;
		}
		fcp = fcp->next;
	}

	ret = real_sys_open(filename, flags, mode);

	return ret;
}

static struct ftrace_hook open_hook = HOOK("sys_open", fh_sys_open, &real_sys_open);

static int resolve_hook_address(struct ftrace_hook *hook){
	hook->address = kallsyms_lookup_name(hook->name);
	if(!hook->address){
		printk("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	*((unsigned long *) hook->original) = hook->address;
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs){
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	if(!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
}

int fh_install_hook (struct ftrace_hook *hook){
	int err;
	err = resolve_hook_address(hook);
	if(err)
		return err;
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if(err){
		printk("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if(err){
		printk("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0); 
		return err;
	}
	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook){
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if(err)
		printk("unregister_ftrace_function() failed: %d\n", err);
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if(err)
		printk("ftrace_set_filter_ip() failed: %d\n", err);
}

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
	char fn[512];
	int access = 0;
	fcontrl *exists = NULL;

	printk(KERN_INFO "PTRAC: Adding to filelist: %s", buf);
	sscanf(buf, "%511s %d", fn, &access);

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
		strncpy(f->fn, fn, 511);
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

	resolve_hook_address(&open_hook);
	fh_install_hook(&open_hook);

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

	fh_remove_hook(&open_hook);
	printk(KERN_INFO "PTRAC: Module unloaded!\n");
}

module_init(ptrac_init);
module_exit(ptrac_exit);
