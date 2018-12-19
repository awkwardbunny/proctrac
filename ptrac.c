#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
//#include <syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brian Hong");
MODULE_DESCRIPTION("Process File Access Tracker Kernel Module");
MODULE_VERSION("0.1");

static char *fn_conf = "/etc/proctrac.conf";
module_param(fn_conf, charp, S_IRUGO);
MODULE_PARM_DESC(fn_conf, "Stored configuration file");

struct file *file_open(const char *path, int flags, int rights);
void file_close(struct file *file);
int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);
int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);
int file_sync(struct file *file);

struct file *fp_conf;
static int __init ptrac_init(void){
	
	printk(KERN_INFO "PTRAC: Module loaded!\n");
	printk(KERN_INFO "PTRAC: Using file %s as config\n", fn_conf);

	printk(KERN_INFO "PTRAC: Opening config file.\n");
	fp_conf = file_open(fn_conf, O_WRONLY | O_CREAT, 0644);
	
	return 0;
}

static void __exit ptrac_exit(void){
	printk(KERN_INFO "PTRAC: Closing config file.\n");
	file_close(fp_conf);

	printk(KERN_INFO "PTRAC: Module unloaded!\n");
}

module_init(ptrac_init);
module_exit(ptrac_exit);

// https://stackoverflow.com/questions/1184274/read-write-files-within-a-linux-kernel-module

struct file *file_open(const char *path, int flags, int rights){
	struct file *fp = NULL;
	mm_segment_t oldfs;
	int err = 0;

	oldfs = get_fs();
	set_fs(get_ds());
	fp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if(IS_ERR(fp)){
		err = PTR_ERR(fp);
		return NULL;
	}
	return fp;
}

void file_close(struct file *file){
	filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size){
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_read(file, data, size, &offset);

	set_fs(oldfs);
	return ret;
}

int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size){
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(file, data, size, &offset);

	set_fs(oldfs);
	return ret;
}

int file_sync(struct file *file){
	vfs_fsync(file, 0);
	return 0;
}
