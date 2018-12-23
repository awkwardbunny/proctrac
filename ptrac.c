#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brian Hong");
MODULE_DESCRIPTION("Process File Access Tracker Kernel Module");
MODULE_VERSION("0.1");

// Helper function to copy string from userspace
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

static long (*sys_getcwd)(char __user *buf, unsigned long size);
static char *resolve_path(char *fn){
	char *buf, *buf2;
	char *cwd;
	int len;

	// No need
	if(fn[0] == '/')
		return fn;

	// Get cwd
	buf = kmalloc(1024, GFP_KERNEL);
	if(!buf) return NULL;
	cwd = d_path(&(current->fs->pwd), buf, 1024);
	len = strlen(cwd);

	// Concatenate two halves
	buf2 = kmalloc(1024, GFP_KERNEL);
	strcpy(buf2, cwd); // cwd
	buf2[len] = '/'; // '/'
	strcpy(buf2+len+1, fn); // filename

	kfree(buf);
	kfree(fn);
	return buf2;
}

// Definition of data structures to keep track of files
typedef struct st_fcontrl fcontrl;
typedef struct st_fcontrl {
	char fn[512];
	int access;
	fcontrl *next;
} fcontrl;
fcontrl *flist = NULL;

// Helper function to search through file linked list
static int search_flist(char *filename){
	fcontrl *fcp = flist;
	while(fcp){
		if(!strcmp(fcp->fn, filename))
			return fcp->access;
		fcp = fcp->next;
	}
	return 0;
}

// Definitions and functions for hooking
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

#define HOOK(_name) \
	{ \
		.name = #_name, \
		.function = hook_##_name, \
		.original = &real_##_name \
	}

static int resolve_hook_address(struct ftrace_hook *hook){
	hook->address = kallsyms_lookup_name(hook->name);
	if(!hook->address){
		printk("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	*((unsigned long *) hook->original) = hook->address;
	return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs){
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	if(!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
}

int install_hook (struct ftrace_hook *hook){
	int err;
	err = resolve_hook_address(hook);
	if(err)
		return err;
	hook->ops.func = ftrace_thunk;
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
	printk(KERN_INFO "PTRAC: Installed hook on %s()\n", hook->name);
	return 0;
}

void remove_hook(struct ftrace_hook *hook){
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if(err)
		printk("unregister_ftrace_function() failed: %d\n", err);
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if(err)
		printk("ftrace_set_filter_ip() failed: %d\n", err);
	printk(KERN_INFO "PTRAC: Removed hook on %s()\n", hook->name);
}

// Hook definitions
static asmlinkage long (*real_sys_open)(const char __user *filename, int flags, umode_t mode);
static asmlinkage long hook_sys_open(const char __user *filename, int flags, umode_t mode){
	long ret;
	char *kfn;

	kfn = dup_fn(filename);
	kfn = resolve_path(kfn);
	if(search_flist(kfn)) printk(KERN_INFO "PTRAC: PID %d is opening %s\n", task_pid_nr(current), kfn);
	kfree(kfn);

	ret = real_sys_open(filename, flags, mode);
	return ret;
}

static asmlinkage long (*real_sys_unlink)(const char __user *filename);
static asmlinkage long hook_sys_unlink(const char __user *filename){
	long ret;
	char *kfn;

	kfn = dup_fn(filename);
	kfn = resolve_path(kfn);
	if(search_flist(kfn)) printk(KERN_INFO "PTRAC: PID %d is unlinking %s\n", task_pid_nr(current), kfn);
	kfree(kfn);

	ret = real_sys_unlink(filename);
	return ret;
}

static asmlinkage long (*real_sys_unlinkat)(int dfd, const char __user *filename, int flag);
static asmlinkage long hook_sys_unlinkat(int dfd, const char __user *filename, int flag){
	long ret;
	char *kfn;

	kfn = dup_fn(filename);
	kfn = resolve_path(kfn);
	if(search_flist(kfn)) printk(KERN_INFO "PTRAC: PID %d is unlinking %s\n", task_pid_nr(current), kfn);
	kfree(kfn);

	ret = real_sys_unlinkat(dfd, filename, flag);
	return ret;
}

// Hooks
static struct ftrace_hook open_hook = HOOK(sys_open);
static struct ftrace_hook unlink_hook = HOOK(sys_unlink);
static struct ftrace_hook unlinkat_hook = HOOK(sys_unlinkat);

// Function handlers for filelist kobject attribute
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

// Kobject and stuff for filelist
struct kobj_attribute kattr = __ATTR_RW(filelist);
struct kobject *kobj_ref;

static int __init ptrac_init(void){

	printk(KERN_INFO "PTRAC: Module loaded!\n");

	// Setup sysfs
	// Create new kobject and register /sys/ptrac
	kobj_ref = kobject_create_and_add("ptrac", NULL);
	
	// Create /sys/ptrac/filelist
	if(sysfs_create_file(kobj_ref, &kattr.attr)){
		printk(KERN_INFO "Cannot create sysfs file...\n");
		return -1;
	}

	sys_getcwd = (long (*)(char __user *buf, unsigned long size))kallsyms_lookup_name("sys_getcwd");

	// Install hooks
	install_hook(&open_hook);
	install_hook(&unlink_hook);
	install_hook(&unlinkat_hook);

	return 0;
}

static void __exit ptrac_exit(void){

	// Remove hooks
	remove_hook(&open_hook);
	remove_hook(&unlink_hook);
	remove_hook(&unlinkat_hook);

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
