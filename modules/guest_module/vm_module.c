/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <uapi/asm/termbits.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <net/busy_poll.h>
#include <linux/statfs.h>
/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0
static DEFINE_SPINLOCK(send_lock);
static DEFINE_SPINLOCK(process_counter_lock);

#define OPEN_REQUEST 0
#define WRITE_REQUEST 1
#define READ_REQUEST 2
#define MMAP_REQUEST 3
#define CLOSE_REQUEST 4
#define LSEEK_REQUEST 5
#define FSTAT_REQUEST 6
#define EXECVE_REQUEST 7
#define IOCTL_REQUEST 8
#define STAT_REQUEST 9
#define STATFS_REQUEST 10
#define FSETXATTR_REQUEST 11
#define POLL_REQUEST 12


#define msg_size 10000
#define HOST_ADDR 524289
#define max_msgs 50
extern void __iomem *regs;
static char* shared;

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION_SAFE.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/*####################################################### Global/static variables  ######################################################## */

static DECLARE_WAIT_QUEUE_HEAD(wq);
static struct task_struct *thread_st;
struct response{
	int length; //important in case of read/write
	char * buffer;
	int open_fd; //opened fd in host
};

struct msg_header
{
	u8 msg_status;
	int pid;
	int host_pid;
	u8 msg_type;
	u16 msg_length;
	int fd;
	size_t count;
	char msg[msg_size];
} ;

struct open_req{ //hack filename size
	int dfd;
	char filename[100];
	int flags;
	umode_t mode;
};

struct ioctl_req{
	unsigned int fd;
	unsigned int cmd;
	unsigned long arg;
	char termios[sizeof(struct termios)];
};
struct lseek_req{
	unsigned int fd;
	off_t offset;
	unsigned int whence;
};
struct fsetxattr_req {//hack size of name and value
	int fd;
	char name[100];
	char value[100];
	size_t size;
	int flags;
};

struct poll_req{
	struct pollfd ufds[10]; //hack number of fds limited by 10
	unsigned int nfds;
	int timeout_msecs;
};

struct process_info{
	int pid;
	int host_pid;
	char wake_flag;
	struct response res[1];
	int fds_open_in_host[10]; //opened fds are noted to direct more request to host on these fds, 0,1,2 fds are not noted
};

static int num_of_watched_processes=11;
static struct process_info watched_processes[11];
static int current_num_of_childs=0;
static struct kobject *sysfs_kobject;
static char newProcessFlag=0;
static int last_host_process_pid;
int sysfs_file_open=1;
/*####################################################### Communication Channel Functions  ######################################################## */
static void copy_bytes(char* dest, char* source, size_t length){
	int i;
	for ( i = 0; i <length ; ++i)
	{
		dest[i] = source[i];
	}
}

static void send_to_host(struct msg_header* header){

	int flag = 0;
	int i;
	if(header==NULL || shared==NULL){
		return;
	}

	while(flag==0){
		for(i=0;i<max_msgs;i++){
			u8 *status;
			if(flag==1)
				break;

			status = (u8*)(shared+HOST_ADDR+sizeof(struct msg_header)*i);
			if(*status == 0 || *status == 2){
				char* base;
				spin_lock(&send_lock);
				base = (char*)status;
                printk("SANDBOX: sending msg to host:msg=%s type=%d fd=%d\n",header->msg,header->msg_type,header->fd);
				copy_bytes(base,(char*)header,sizeof(struct msg_header));
				flag=1;
				kfree(header);
				spin_unlock(&send_lock);
			}
		}
	}

	return;
}


static void receive_from_host(void){
	int i;
	struct msg_header* msg = kmalloc(sizeof(struct msg_header),GFP_KERNEL);

	if(shared==NULL){
		return;
	}

	for(i=0;i<max_msgs;i++){

		char* temp = (char*)(shared+sizeof(struct msg_header)*i);
		//int* check = (int*)(temp+1);
		copy_bytes((char*)msg,temp,sizeof(struct msg_header));

		if(msg->msg_status == 1){

			char* r = kmalloc(msg->msg_length*sizeof(char),GFP_KERNEL);
			int index=0;
			memcpy(r,msg->msg,msg->msg_length);

			printk("SANDBOX: Got message from host, pid %d , length as %d and type as %d and host fd=%d and msg = %s\n",msg->pid,msg->msg_length,msg->msg_type,msg->fd,r);
			if(msg->msg_type == EXECVE_REQUEST && msg->pid == 0 ){
				last_host_process_pid = msg->host_pid;
				newProcessFlag=1;
				*temp = 2;   // this should be done at last
			}
			else{
				int j;
				for(j=0;j<num_of_watched_processes;j++){
					if(watched_processes[j].pid == msg->pid ){
						index = j;
						break;
					}
				}
				watched_processes[index].res[0].length = msg->msg_length;
				watched_processes[index].res[0].buffer = r;
				watched_processes[index].res[0].open_fd = msg->fd;
				watched_processes[index].wake_flag = 'y';
				*temp = 2;   // this should be done at last
				wake_up(&wq);
			}


		}
	}

	kfree(msg);
	return;

}

static int thread_fn(void *unused)
{
    while (!kthread_should_stop())
    {
        schedule_timeout_interruptible(5);
		receive_from_host();
    }
    printk("SANDBOX: Thread Stopping\n");
    return 0;
}

/*####################################################### Hooked Functions ################################################ */


static int ksys_write_to_host(unsigned int fd, const char __user *buf, size_t count,int i)
{
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = WRITE_REQUEST;
	header->msg_length = strlen(buf);
	header->fd = fd;
	header->count = count;
	memcpy(header->msg,buf,count);
	send_to_host(header);
	return count;
}


static asmlinkage ssize_t ksys_read_from_host(unsigned int fd, const char __user *buf, size_t count,int i)
{

	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = READ_REQUEST;
	header->msg_length = count;
	header->fd = fd;
	header->count = count;
	send_to_host(header);

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	if(watched_processes[i].res[0].length < 0){  //errorno is not yet set
		return -1;
	}
	else{
		copy_to_user( (void __user *) buf,(const void *)watched_processes[i].res[0].buffer, (unsigned long) watched_processes[i].res[0].length);
		kfree(watched_processes[i].res[0].buffer);
		return watched_processes[i].res[0].length;
	}
}

static asmlinkage long ksys_open_in_host(int dfd, const char __user *filename, int flags, umode_t mode,int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	struct open_req* open_r = kmalloc(sizeof(struct open_req),GFP_KERNEL);
	int j;
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = OPEN_REQUEST;
	header->msg_length = sizeof(struct open_req);

	open_r->dfd =dfd;
	strcpy(open_r->filename,filename);                                         //size not checked <=100 , needs to be changed
    open_r->flags = flags;
	open_r->mode = mode;
	memcpy(header->msg , (char *) open_r,sizeof(struct open_req));
	send_to_host(header);

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';
	for(j=0;j<10;j++){//hack assumed to be 10 fds opened at max
		if(watched_processes[i].fds_open_in_host[j]==-1){
			watched_processes[i].fds_open_in_host[j]=watched_processes[i].res[0].open_fd;
			break;
		}
	}
	if(watched_processes[i].res[0].open_fd < 0){  //errorno is not yet set
		kfree(watched_processes[i].res[0].buffer);
		return -1;
	}
	else{
		kfree(watched_processes[i].res[0].buffer);
		return watched_processes[i].res[0].open_fd;
	}
}

static asmlinkage int ksys_close_in_host(int fd, int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	int j;
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = CLOSE_REQUEST;
	header->msg_length = 0;
	header->fd = fd;
	for(j=0;j<10;j++){
		if(watched_processes[i].fds_open_in_host[j]==fd){
			watched_processes[i].fds_open_in_host[j]=-1;
			break;
		}
	}
	send_to_host(header);
	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	kfree(watched_processes[i].res[0].buffer);
	return watched_processes[i].res[0].open_fd; //open_fd is used for checking if file closed in host properly or not

}

// static asmlinkage int ioctl_in_host(unsigned int fd, unsigned int cmd, unsigned long arg, int i){
// 	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
// 	header->pid = watched_processes[i].pid;
// 	header->host_pid = watched_processes[i].host_pid;
// 	header->msg_status = 1;
// 	header->msg_type = IOCTL_REQUEST;
// 	struct ioctl_req* ioctl_r = kmalloc(sizeof(struct ioctl_req),GFP_KERNEL);
// 	ioctl_r->fd =fd;
// 	ioctl_r->arg=arg;
// 	ioctl_r->cmd = cmd;
// 	copy_from_user(ioctl_r->termios,(char*)arg,sizeof(struct termios));

// 	struct termios* rr = (struct termios*)ioctl_r->termios;
// 	printk("Ioctl termios args %ld and %ld and command is %u and fd is %d\n",rr->c_iflag,rr->c_cflag,cmd,fd);

// 	memcpy(header->msg , (char *) ioctl_r,sizeof(struct ioctl_req));
// 	header->msg_length = sizeof(struct ioctl_req);
// 	send_to_host(header);
// 	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
// 	watched_processes[i].wake_flag = 'n';

// 	copy_to_user((void __user *)arg,(char*)watched_processes[i].res[0].buffer,sizeof(struct termios));
// 	kfree(watched_processes[i].res[0].buffer);
// 	return watched_processes[i].res[0].open_fd; //open_fd is used for checking if file ioctl in host properly or not
// }

static asmlinkage int fstat_in_host(unsigned int fstat_fd, struct kstat * statbuf, int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = FSTAT_REQUEST;
	header->fd = fstat_fd;

	header->msg_length = 0;
	send_to_host(header);
	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	struct kstat * dum=(struct kstat *)(watched_processes[i].res[0].buffer);
	printk("check3 size=%d\n",dum->size);
	memcpy((void *)statbuf,(void *)watched_processes[i].res[0].buffer,sizeof(struct kstat));
	kfree(watched_processes[i].res[0].buffer);
	return watched_processes[i].res[0].open_fd;
}
static asmlinkage int stat_in_host(const char __user * filename, struct kstat * stat, int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = STAT_REQUEST;
	header->msg_length = strlen(filename);
	memcpy(header->msg,filename,header->msg_length);

	send_to_host(header);
	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	struct kstat * dum=(struct kstat *)(watched_processes[i].res[0].buffer);
	memcpy((void *)stat,(void *)watched_processes[i].res[0].buffer,sizeof(struct kstat));
	kfree(watched_processes[i].res[0].buffer);
	return watched_processes[i].res[0].open_fd;
}
static asmlinkage int statfs_in_host(const char __user * pathname, struct kstatfs * st, int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = STATFS_REQUEST;
	header->msg_length = strlen(pathname);
	memcpy(header->msg,pathname,header->msg_length);

	send_to_host(header);
	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	struct kstatfs * dum=(struct kstatfs *)(watched_processes[i].res[0].buffer);
	memcpy((void *)st,(void *)watched_processes[i].res[0].buffer,sizeof(struct kstatfs));
	kfree(watched_processes[i].res[0].buffer);
	return watched_processes[i].res[0].open_fd;
}

static asmlinkage long lseek_in_host(unsigned int fd,off_t offset,unsigned int whence,int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	struct lseek_req* lseek_r = kmalloc(sizeof(struct lseek_req),GFP_KERNEL);
	int j;
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = LSEEK_REQUEST;
	header->msg_length = sizeof(struct lseek_req);

	lseek_r->fd =fd;
	lseek_r->offset =offset;
	lseek_r->whence =whence;

	memcpy(header->msg , (char *) lseek_r,sizeof(struct lseek_req));
	send_to_host(header);

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	return watched_processes[i].res[0].open_fd;
}
static asmlinkage long fsetxattr_in_host(int fd,const char __user * name,const void __user * value,size_t size,int flags,int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	struct fsetxattr_req* fsetxattr_r = kmalloc(sizeof(struct fsetxattr_req),GFP_KERNEL);
	int j;
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = FSETXATTR_REQUEST;
	header->msg_length = sizeof(struct fsetxattr_req);

	fsetxattr_r->fd =fd;
	memcpy(fsetxattr_r->name,name,strlen(name));
	memcpy(fsetxattr_r->value,value,strlen(value)); //value may not str hack
	fsetxattr_r->size =size;
	fsetxattr_r->flags =flags;

	memcpy(header->msg , (char *) fsetxattr_r,sizeof(struct fsetxattr_req));
	send_to_host(header);

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	return watched_processes[i].res[0].open_fd;
}
static asmlinkage long poll_in_host(struct pollfd __user * ufds,unsigned int nfds,int timeout_msecs,int i){
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	struct poll_req* poll_r = kmalloc(sizeof(struct poll_req),GFP_KERNEL);
	int k;
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = POLL_REQUEST;
	header->msg_length = sizeof(struct poll_req);

	poll_r->nfds =nfds;
	poll_r->timeout_msecs =timeout_msecs;
	struct pollfd * curfd=ufds;
	for(k=0;k<nfds;k++){
		poll_r->ufds[k]=*curfd;
		curfd+=1;
	}

	memcpy(header->msg , (char *) poll_r,sizeof(struct poll_req));
	send_to_host(header);

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	return watched_processes[i].res[0].open_fd;
}


/*############################################################## Hooked Functions #################################################### */

int vmmod_filemap_fault( struct vm_fault *vmf )
{
	struct page *page = NULL;
	unsigned long offset;
	unsigned long required_page_of_file;
	struct vm_area_struct *vma = vmf->vma;
	struct file * file1;
	printk("SANDBOX: vmmod mmap fault handler called\n");
	offset = (((unsigned long)vmf->address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT));
	required_page_of_file=offset >> PAGE_SHIFT;
	page = alloc_page(vmf->gfp_mask);
	unsigned long page_va=__va(page_to_pfn(page) << PAGE_SHIFT);

	//get content of page from host

	int i;
	for(i=0;i<num_of_watched_processes;i++){
		if(watched_processes[i].pid == current->pid)
			break;
	}
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = MMAP_REQUEST;
	file1=vma->vm_file;
	if(file1){
		int j;
		for(j=3;j<=50;j++){//loop over 50 files. //hack 50 fds limit
			if(fdget(j).file==file1){
				break;
			}
		}
		header->fd =j;
	}
	else{
		printk("SANDBOX: no vma file");
	}
	header->count = required_page_of_file;
	send_to_host(header);

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	//got page content
	if(watched_processes[i].res[0].length < 0){  //errorno is not yet set
		return 0;
	}
	printk("SANDBOX: fault data=%s\n",watched_processes[i].res[0].buffer);
	memcpy(page_va,watched_processes[i].res[0].buffer, (unsigned long) watched_processes[i].res[0].length);
	kfree(watched_processes[i].res[0].buffer);

	vmf->page = page;
	return 0;
}

int vmmod_filemap_page_mkwrite( struct vm_fault *vmf )
{
	printk("SANDBOX: filemap_page_mkwrite called\n");
    return VM_FAULT_LOCKED;
}
void vmmod_filemap_map_pages(struct vm_fault *vmf,
		pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	printk("SANDBOX: filemap_map_pages called\n");
}
static struct vm_operations_struct vmmod_file_vm_ops = {
    .fault = vmmod_filemap_fault,
    .map_pages = vmmod_filemap_map_pages,
    .page_mkwrite = vmmod_filemap_page_mkwrite,
};

int mmap_from_host(struct file * f, struct vm_area_struct * vma){
	printk("SANDBOX: mmap_from_host reached %lu %lusize=%lu\n",vma->vm_start,vma->vm_end,vma->vm_end-vma->vm_start);//
	struct file * file1=vma->vm_file;
	int i;
	unsigned long startaddr=vma->vm_start;
	unsigned int file1_fd=3;
	vma->vm_ops = &vmmod_file_vm_ops;

	for(i=0;i<num_of_watched_processes;i++){
		if(watched_processes[i].pid == current->pid)
			break;
	}
	if(file1){
		int j;
		for(j=3;j<=50;j++){//loop over 50 files.
			if(fdget(j).file==file1){
				break;
			}
		}
		file1_fd =j;
	}
	while(startaddr < vma->vm_end){
		int remap_ret;
		unsigned long offset = (((unsigned long)startaddr - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT));

		unsigned long required_page_of_file=offset >> PAGE_SHIFT;
		printk("loop %d %d\n",offset,required_page_of_file);
		struct page * page=alloc_page(GFP_KERNEL);
		unsigned long page_pfn =page_to_pfn(page);
		unsigned long page_va=__va( page_pfn<< PAGE_SHIFT);
			//get content of page from host
		struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
		header->pid = watched_processes[i].pid;
		header->host_pid = watched_processes[i].host_pid;
		header->msg_status = 1;
		header->msg_type = MMAP_REQUEST;
		header->fd =file1_fd;
		header->count = required_page_of_file;
		send_to_host(header);

		wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
		watched_processes[i].wake_flag = 'n';

		//got page content
		if(watched_processes[i].res[0].length < 0){  //errorno is not yet set
			return -EIO;
		}
		printk("SANDBOX: fault data len=%lu data=%s \n",watched_processes[i].res[0].length,watched_processes[i].res[0].buffer);
		memcpy(page_va,watched_processes[i].res[0].buffer, (unsigned long) watched_processes[i].res[0].length);
		printk("hello1\n");
		kfree(watched_processes[i].res[0].buffer);
		printk("hello2 %lu, %lu\n",startaddr, page_pfn);
		//remap_ret = remap_pfn_range(vma, startaddr,page_pfn, watched_processes[i].res[0].length, vma->vm_page_prot); // maps physical area to user address space in user page table.
		WARN_ON(!page_count(page));
		remap_ret = vm_insert_page(vma, startaddr,page);
		printk("hello3 %d\n",remap_ret);

		if (remap_ret < 0) {
			pr_err("could not map the address area\n");
			return -EIO;
		}
		startaddr+=PAGE_SIZE;
	}
	return 0;
}
static struct file_operations vmmod_fops = {
 .mmap=  mmap_from_host
};



static asmlinkage int RFS_syscall(int syscall_code, void * argptr)
{
	int watched_process_flag = 0;
	int i;
	for(i=0;i<num_of_watched_processes;i++){
		if(watched_processes[i].pid == current->pid){
			watched_process_flag=1;
			break;
		}
	}

	if(!watched_process_flag){
		return -5000;
	}

	switch (syscall_code)
			{
				case VFS_OPEN: {
					struct file *filp = NULL;
					struct arg_open * arg = (struct arg_open *)argptr;
					int vm_fd;
					mm_segment_t fs;
					int j;
					int host_fd=ksys_open_in_host(arg->dfd, arg->filename,arg->flags,arg->mode,i);
					if(host_fd>=0){
						fs = get_fs();
						set_fs(KERNEL_DS);
						vm_fd = do_sys_open(arg->dfd,"/home/dummy", arg->flags, arg->mode);
						set_fs(fs);

						printk("SANDBOX: vmfd=%d\n",vm_fd);
						filp=(fdget(vm_fd)).file;
						filp->f_op=&vmmod_fops;
						watched_processes[i].fds_open_in_host[vm_fd]=host_fd;
					}
					return vm_fd;
					break;
				}
				case VFS_READ: {
					struct arg_read * arg = (struct arg_read *) argptr;
					if(watched_processes[i].fds_open_in_host[arg->fd]!=-1)
						return ksys_read_from_host(watched_processes[i].fds_open_in_host[arg->fd],arg->buf,arg->count,i);
					break;
				}
				case VFS_WRITE: {
					struct arg_write * arg = (struct arg_write *) argptr;
					if(watched_processes[i].fds_open_in_host[arg->fd]!=-1)
						return ksys_write_to_host(watched_processes[i].fds_open_in_host[arg->fd],arg->buf,arg->count,i);
					break;
				}
				case VFS_CLOSE: {
					struct arg_close * arg = (struct arg_close *) argptr;
					if(arg->fd==3 && sysfs_file_open==1){
						sysfs_file_open=0;
						return -5000;
					}
					if(watched_processes[i].fds_open_in_host[arg->fd]!=-1){ // close at both places
						int dummy=ksys_close_in_host(watched_processes[i].fds_open_in_host[arg->fd],i);
						watched_processes[i].fds_open_in_host[arg->fd]=-1;
						return -5000;
					}
					break;
				}
				case VFS_FSTAT: {
					struct arg_fstat * arg = (struct arg_fstat *) argptr;
					if(watched_processes[i].fds_open_in_host[arg->fd]!=-1){
						int fstatret=fstat_in_host(watched_processes[i].fds_open_in_host[arg->fd],arg->stat,i);
						return fstatret;
					}
					break;
				}
				case VFS_STAT: {
					struct arg_stat * arg = (struct arg_stat *) argptr;
					int statret=stat_in_host(arg->filename,arg->stat,i);
					return statret;
					break;
				}
				case VFS_STATFS: {
					struct arg_statfs * arg = (struct arg_statfs *) argptr;
					int statfsret=statfs_in_host(arg->pathname,arg->st,i);
					return statfsret;
					break;
				}
				case VFS_LSEEK: {
					struct arg_lseek * arg = (struct arg_lseek *) argptr;
					if(watched_processes[i].fds_open_in_host[arg->fd]!=-1)
						return lseek_in_host(watched_processes[i].fds_open_in_host[arg->fd],arg->offset,arg->whence,i);
					break;
				}
				case VFS_FSETXATTR: {
					struct arg_fsetxattr * arg = (struct arg_fsetxattr *) argptr;
					if(watched_processes[i].fds_open_in_host[arg->fd]!=-1)
						return fsetxattr_in_host(watched_processes[i].fds_open_in_host[arg->fd],arg->name,arg->value,arg->size,arg->flags,i);
					break;
				}
				case VFS_POLL: {
					struct arg_poll * arg = (struct arg_poll *) argptr;
					if(watched_processes[i].fds_open_in_host[arg->ufds->fd]!=-1){ //checking just first fd, hack for wget
						return poll_in_host(arg->ufds,arg->nfds,arg->timeout_msecs,i);
					}
					break;
				}
			}
     return -5000;
}
// static asmlinkage ssize_t (*real_ksys_write)(unsigned int fd, const char __user *buf, size_t count);

// static asmlinkage ssize_t fake_ksys_write(unsigned int fd, const char __user *buf, size_t count)
// {

// 	int watched_process_flag = 0;  //flag if this function is called by ssh proxy child
// 	int i;
// 	for(i=0;i<num_of_watched_processes;i++){
// 		if(watched_processes[i].pid == current->pid){
// 			watched_process_flag=1;
// 			break;
// 		}
// 	}

// 	if(watched_process_flag){
// 		int j;
// 		for(j=0;j<10;j++){
// 			if(watched_processes[i].fds_open_in_host[j]==fd)
// 				return ksys_write_to_host(fd,buf,count,i);
// 		}
// 		return real_ksys_write(fd, buf,count);
// 	}
// 	else{
// 			return real_ksys_write(fd, buf,count);
// 	}

// }

// static asmlinkage ssize_t (*real_ksys_read)(unsigned int fd, const char __user *buf, size_t count);

// static asmlinkage ssize_t fake_ksys_read(unsigned int fd, const char __user *buf, size_t count)
// {
// 	int watched_process_flag = 0;
// 	int i;
// 	for(i=0;i<num_of_watched_processes;i++){
// 		if(watched_processes[i].pid == current->pid){
// 			watched_process_flag=1;
// 			break;
// 		}
// 	}

// 	if(watched_process_flag){
// 		int j;
// 		for(j=0;j<10;j++){
// 			if(watched_processes[i].fds_open_in_host[j]==fd)
// 				return ksys_read_from_host(fd,buf,count,i);
// 		}
// 		return real_ksys_read(fd,buf,count);
// 	}
// 	else{
// 		return real_ksys_read(fd, buf,count);
// 	}

// }

//static asmlinkage long (*real_sys_open)(int dfd, const char __user *filename, int flags, umode_t mode);

// static asmlinkage long fake_sys_open(int dfd, const char __user *filename, int flags, umode_t mode){
// 	int watched_process_flag = 0;
// 	int i;
// 	for(i=1;i<num_of_watched_processes;i++){   //checking open call from children only, not agent
// 		if(watched_processes[i].pid == current->pid){
// 			watched_process_flag=1;
// 			break;
// 		}
// 	}
// 	char buffer[7];
// 	copy_from_user((void *)buffer, (const void __user *) filename, (unsigned long) 6);

// 	if(watched_process_flag && (strncmp(buffer, "README", 6) == 0)){
// 		return ksys_open_in_host(dfd, filename,flags,mode,i);
// 	}
// 	else{
// 		return real_sys_open(dfd, filename,flags,mode);
// 	}
// }


// static asmlinkage int (*real_close)(struct files_struct *files, unsigned fd);
// static asmlinkage int fake_close(struct files_struct *files, unsigned fd){
// 	int watched_process_flag = 0;
// 	int i;
// 	for(i=1;i<num_of_watched_processes;i++){
// 		if(watched_processes[i].pid == current->pid){
// 			watched_process_flag=1;
// 			break;
// 		}
// 	}
// 	if(watched_process_flag){
// 		int j;
// 		for(j=0;j<10;j++){
// 			if(watched_processes[i].fds_open_in_host[j]==fd){
// 				return ksys_close_in_host(fd,i);
// 			}
// 		}
// 		return real_close(files,fd);
// 	}
// 	else{
// 		return real_close(files,fd);
// 	}
// }


// static asmlinkage int (*real_ioctl) (unsigned int fd, unsigned int cmd, unsigned long arg);
// static asmlinkage int fake_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg){
// 	int watched_process_flag = 0;
// 	int i;
// 	for(i=1;i<num_of_watched_processes;i++){
// 		if(watched_processes[i].pid == current->pid){
// 			watched_process_flag=1;
// 			break;
// 		}
// 	}
// 	if(watched_process_flag){
// 		int j;
// 		for(j=0;j<10;j++){
// 			if(watched_processes[i].fds_open_in_host[j]==fd)
// 				return ioctl_in_host(fd,cmd,arg,i);
// 		}
// 		return real_ioctl(fd,cmd,arg);
// 	}
// 	else{
// 		return real_ioctl(fd,cmd,arg);
// 	}
// }


/*############################################################## HOOKS ####################################################### */

#define HOOK(_name, _function, _original)	\
	{					\
		.name = (_name),		\
		.function = (_function),	\
		.original = (_original),	\
	}

//static struct ftrace_hook demo_hooks[] = {
	// HOOK("ksys_write", fake_ksys_write, &real_ksys_write),
	// HOOK("ksys_read", fake_ksys_read, &real_ksys_read),
	//HOOK("do_sys_open", fake_sys_open, &real_sys_open),
	// HOOK("__close_fd",fake_close,&real_close),
	// HOOK("ksys_ioctl",fake_ioctl,&real_ioctl),
//};

/*####################################################### Sysfs show and store ##############################################*/

// static char sysfs_file[1024];
static ssize_t sysfs_vmmod_read(struct kobject *kobj, struct kobj_attribute *attr,
                      char *buf)
{
		if(current->pid==watched_processes[0].pid && newProcessFlag==1){
			newProcessFlag=0;
			return 1;
		}
        return 0;
}

static ssize_t sysfs_vmmod_write(struct kobject *kobj, struct kobj_attribute *attr,
                      const char *buf, size_t count)
{
		if(strncmp(buf, "iamagent", 8) == 0){
			watched_processes[0].pid = current->pid;
			watched_processes[0].host_pid = 0;
			printk("SANDBOX: agent created with pid = %d \n",current->pid);
			return count;
		}
		else if(strncmp(buf, "iamchild", 8) == 0){
			spin_lock(&process_counter_lock);
			current_num_of_childs+=1;
			watched_processes[current_num_of_childs].host_pid = last_host_process_pid;
			watched_processes[current_num_of_childs].pid = current->pid;
			printk("SANDBOX: agent forked child with pid = %d \n",current->pid);
			spin_unlock(&process_counter_lock);
			return count;
		}else{
			 printk("Bad SysFS ops... \n");
			 return -EINVAL;
		}

}


static struct kobj_attribute vmmod_attribute =__ATTR(vmmod_file, 0660, sysfs_vmmod_read,sysfs_vmmod_write);



/*####################################################### Module Initialization ##############################################*/
static int fh_init(void)
{
	int err;
	int i;
	shared = (char*)regs;
	// err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	// if (err)
	// 	return err;

	for(i=0;i<num_of_watched_processes;i++){
		int j;
		watched_processes[i].pid = -1;
		watched_processes[i].wake_flag = 'n';        //-1 implies no request yet
		watched_processes[i].res[0].length = -1;

		watched_processes[i].fds_open_in_host[0]=0;
		watched_processes[i].fds_open_in_host[1]=1;
		watched_processes[i].fds_open_in_host[2]=2;

		if(i==0){
			watched_processes[i].fds_open_in_host[0]=-1;
			watched_processes[i].fds_open_in_host[1]=-1;
			watched_processes[i].fds_open_in_host[2]=-1;
		}
		for(j=3;j<10;j++){
			watched_processes[i].fds_open_in_host[j]=-1;
		}
	}
	VFS_syscall=RFS_syscall;
	sysfs_kobject = kobject_create_and_add("sysfs_kobject",
                                                 kernel_kobj);
	if(!sysfs_kobject)
			return -ENOMEM;

	err = sysfs_create_file(sysfs_kobject, &vmmod_attribute.attr);
	if (err) {
		pr_debug("failed to create the foo file in /sys/kernel/sysfs_kobject \n");
		return err;
	}


	pr_info("SANDBOX: module loaded\n");

	printk("SANDBOX: Creating KThread\n");
    thread_st = kthread_run(thread_fn, NULL, "mythread");
    if (!IS_ERR(thread_st)){
           printk("SANDBOX: Thread Created successfully\n");
    }
	else{
	    printk("SANDBOX: Thread creation failed\n");
	thread_st = NULL;
	}

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	//fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (thread_st){
           kthread_stop(thread_st);
           printk("SANDBOX: Thread stopped\n");
   	}
	VFS_syscall=NULL;
	kobject_put(sysfs_kobject);
	pr_info("SANDBOX: module unloaded\n");
}
module_exit(fh_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cam Macdonell");
