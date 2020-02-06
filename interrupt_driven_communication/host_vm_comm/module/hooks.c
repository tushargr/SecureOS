#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/path.h>
#include<linux/slab.h>
#include<linux/sched.h>
#include<linux/uaccess.h>
#include<linux/device.h>
#include <linux/binfmts.h>
#include <linux/ftrace.h>

#include "hostmod.h"

static struct shinfo *shm;


#if 0
static int do_exec_process(struct shinfo *shm)
{
   return -1;
}

static asmlinkage void (*real_finalize_exec)(struct linux_binprm *bprm);
static asmlinkage void fake_finalize_exec(struct linux_binprm *bprm)
{

   BUG_ON(!shm);
   if(strncmp(bprm->filename, "/usr/bin/ssh", 12) || do_exec_process(shm))
      real_finalize_exec(bprm);
   
   return;      
    
}

static struct ftrace_hook exec_hook = {
                                        .name = "finalize_exec",
                                        .function = &fake_finalize_exec, 
                                        .original = &real_finalize_exec
                                       };

static void fh_remove_hook(struct ftrace_hook *hook)
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

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
        hook->address = kallsyms_lookup_name(hook->name);

        if (!hook->address) {
                pr_debug("unresolved symbol: %s\n", hook->name);
                return -ENOENT;
        }

        *((unsigned long*) hook->original) = hook->address;

        return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct pt_regs *regs)
{
        struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

        if (!within_module(parent_ip, THIS_MODULE))
                regs->ip = (unsigned long) hook->function;
}
int install_hooks(void)
{
    int err;
    if(fh_resolve_hook_address(&exec_hook) < 0)
           return -EINVAL;

     exec_hook.ops.func = fh_ftrace_thunk;
     exec_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS
                        | FTRACE_OPS_FL_RECURSION_SAFE
                        | FTRACE_OPS_FL_IPMODIFY;

     err = ftrace_set_filter_ip(&exec_hook.ops, exec_hook.address, 0, 0);
     if(err) {
                pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
                return err;
     }

     err = register_ftrace_function(&exec_hook.ops);
     if (err) {
                pr_debug("register_ftrace_function() failed: %d\n", err);
                ftrace_set_filter_ip(exec_hook.ops, exec_hook.address, 1, 0);
                return err;
     }

     return 0;
}

#endif
struct msg_header* get_send_msg_desc(struct shinfo *sh)
{
        struct msg_header* msg;
        int i;
retry:
        msg = sh->send_ptr; 
        for(i=0; i < (sh->num_descs >> 1); i++){
             if(msg->msg_status == FREE || msg->msg_status == CONSUMED){
                    mutex_lock(&sh->send_lock);
                    msg->msg_status = USED;
                    mutex_unlock(&sh->send_lock);
                    return msg;
             }
             msg = (struct msg_header *)((char *)msg  + MSG_SIZE);
        }
       
       if(unlikely(i == (sh->num_descs >> 1))){
                  schedule_timeout_interruptible(5);
                  goto retry;
       }

 /*Will not come here. GCC shutup*/
      return msg;
}

struct msg_header *recv_msg(struct shinfo *sh, int *more)
{
    struct msg_header* msg;
    int i;
    *more = 1;
    msg = sh->recv_ptr; 
    for(i=0; i < (sh->num_descs >> 1); i++){
            if(msg->msg_status == USED){
                    if(i == (sh->num_descs >> 1) - 1)
                        *more = 0;
                    return msg;
             }
             msg = (struct msg_header *)((char *)msg  + MSG_SIZE);
    }
   
    *more = 0;
    return NULL;       

}

static void initialize_process_info(struct shinfo *sh)
{
   int ctr;

   for(ctr=0; ctr<MAX_PROCESS; ++ctr){
            struct process_info *info = &sh->processes[ctr];
            int ctr1;
            info->pid = -1;
            info->ready = 1;
            info->wake_flag = 'n';
            info->res.length = -1;                 // -1 implies no response yet
            info->res.type = -1;
            info->res.fd = -1;
            info->res.count = 0;
            info->res.pid = 0;
            
            for(ctr1=0; ctr1<MAX_OPEN_FILES; ++ctr1){
                 struct open_file *file = &info->open_files[ctr1];
                 file->host_fd = -1;
                 file->guest_fd = -1;
                 file->filp = NULL;
            }
   }
   return; 
}
struct shinfo* init(void)
{

  shm = kmalloc(sizeof(struct shinfo), GFP_KERNEL);
  
  shm->mem = get_shm_info(&shm->size);
  shm->send_ptr = shm->mem;

  shm->num_descs = shm->size >> MSG_SHIFT;
  
  shm->recv_ptr = shm->send_ptr + (shm->num_descs << 13);       

  initialize_process_info(shm); 
  
  mutex_init(&shm->send_lock);
  mutex_init(&shm->copy_lock);

  init_waitqueue_head(&shm->wq);

  spin_lock_init(&shm->process_lock);
/*
  if(install_hooks() < 0){
       printk(KERN_INFO "Hooks can not be registered\n");
       kfree(shm);
       return NULL;
  } */
  return shm;
}

int shutdown()
{
//   fh_remove_hook(&exec_hook);
   kfree(shm);
   return 0;
}
