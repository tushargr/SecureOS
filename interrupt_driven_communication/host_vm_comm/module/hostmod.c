#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/path.h>
#include<linux/slab.h>
#include<linux/sched.h>
#include<linux/kprobes.h>
#include<linux/uaccess.h>
#include<linux/device.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include "hostmod.h"

#define max_shm_processes 5
static DEFINE_MUTEX(sendmsg_lock1);
static DEFINE_MUTEX(sendmsg_lock2);
static DEFINE_MUTEX(notify_vm_lock);
struct mutex message_array_lock[max_shm_processes];
static struct task_struct *thread_st;
static DECLARE_WAIT_QUEUE_HEAD(wq);

struct shm_information{
                         int vmfd;
                         int shmfd;
                         int host_eventfd;
                         int guest_eventfd;
                         void *shmhandle;
                         unsigned long size;
                         int pid_mapping[max_shm_processes];
                         int message_count[max_shm_processes];
                         void *receive_handle;
                         void *send_handle;
                         int metadata_size;
                         int slot_size;
};
atomic_t in_kernel;
static struct shm_information *shinfo = NULL;
static struct file * g_efilp, *h_efilp;

static int thread_func(struct shm_information *shm){
    int i;
    loff_t pos;
    int shm_slot;
    char *ptr = (char *) kmalloc(10,GFP_KERNEL);

    struct fd f = fdget(shm->guest_eventfd);
    g_efilp = f.file;
    BUG_ON(!g_efilp);
    printk(KERN_INFO "gefd flags = %x\n", g_efilp->f_flags);

    f  = fdget(shm->host_eventfd);
    h_efilp = f.file;
    BUG_ON(!h_efilp);
    printk(KERN_INFO "hefd flags = %x\n", h_efilp->f_flags);

    while (!kthread_should_stop()){
        pos=0;
        shm_slot=-1;
        h_efilp->f_flags &= ~O_NONBLOCK;
        WARN_ON(kernel_read(h_efilp, ptr, 8, &pos) != 8);
        stac();

        //get_shm_slot
        char * metadata_ptr = (char *)shinfo->receive_handle;
        for(i=0;i<max_shm_processes;i++){
            if(*metadata_ptr == '1'){
              *metadata_ptr = '0';
              shm_slot=i;
              break;
            }
            metadata_ptr++;
        }
        BUG_ON(shm_slot==-1)
        clac();

        //wake up process
        mutex_lock(&(message_array_lock[shm_slot]));
        shinfo->message_count[shm_slot]+=1;
        mutex_unlock(&(message_array_lock[shm_slot]));
        wake_up(&wq);
        //schedule_timeout_interruptible(5);
    }
    free(ptr);
    printk("SANDBOX: Thread Stopping\n");
    return 0;
}

int notify_vm(int shm_slot){
  char *ptr = (char *) kmalloc(10,GFP_KERNEL);
  loff_t pos = 0;

  stac();
  *(((char *)shinfo->send_handle)+shm_slot)='1';
  clac();

  *((unsigned long *) ptr) = 1;

  if(kernel_write(g_efilp, ptr, 8, &pos) != 8){
     return -EINVAL;
  }
  return 0;
}

int get_shm_slot(){
    int shm_slot=-1;
    for(i=1;i<max_shm_processes;i++){
        if(shinfo->pid_mapping[i]==current->pid){
            shm_slot=i;
            break;
        }
    }
    return shm_slot;
}

void put_msg_on_shm(int shm_slot, void * msg, unsigned long size){
    char * slot_handle = ((char *)shinfo->send_handle) + shinfo->metadata_size + shm_slot * shinfo->slot_size;
    unsigned long tail_offset = *(((unsigned long *)slot_handle)+1);
    char * ptr = slot_handle+tail_offset;
    if(shinfo->slot_size - tail_offset >= size + sizeof(unsigned long)){
        stac();
        *((unsigned long *)ptr)=size;
        ptr += sizeof(unsigned long);
        memcpy((void *) ptr,msg,size);
        clac();
        tail_offset=tail_offset+sizeof(unsigned long)+size;
        if(tail_offset >= shinfo->slot_size)
            tail_offset= 2 * sizeof(unsigned long);
    }
    else{
        stac();
        *((unsigned long *)ptr)=-1;
        clac();
        ptr = slot_handle + 2 * sizeof(unsigned long);
        stac();
        *((unsigned long *)ptr)=size;
        ptr += sizeof(unsigned long);
        memcpy((void *) ptr,msg,size);
        clac();
        tail_offset = 3 * sizeof(unsigned long)+size;
    }

    stac();
    *(((unsigned long *)slot_handle)+1)=tail_offset;
    clac();

    return;
}

int sendmsg(void * msg, unsigned long size){
  //check if process pid present in pid_mappings
    int i;
    int shm_slot=get_shm_slot();
    int first_time = (shm_slot ==-1)?1:0;

    if(first_time){
        //get free slot for new process with lock
        int freeslot=-1;
        mutex_lock(&sendmsg_lock1);
        for(i=1;i<max_shm_processes;i++){
            if(pid_mapping[i]==-1){
                freeslot=i;break;
            }
        }
        BUG_ON(freeslot==-1);
        pid_mapping[freeslot]=current->pid;
        mutex_unlock(&sendmsg_lock1);

        //modify msg to include allotted slot
        void * modified_msg= kmalloc(size+sizeof(int),GFP_KERNEL);
        *((int *) modified_msg) = freeslot;
        if(msg!=NULL && size!=0){
            memcpy( (void *)(((int *)modified_msg)+1),msg,size);
        }

        //put message on 0th slot with lock
        mutex_lock(&sendmsg_lock2);
        put_msg_on_shm(0,modified_msg,size+sizeof(int));
        mutex_unlock(&sendmsg_lock2);
        kfree(modified_msg);

        mutex_lock(&notify_vm_lock);
        notify_vm(0);
        mutex_unlock(&notify_vm_lock);
    }
    else{
        put_msg_on_shm(shm_slot,msg,size);

        mutex_lock(&notify_vm_lock);
        notify_vm(shm_slot);
        mutex_unlock(&notify_vm_lock);
    }
    return 1;
}

void * receivemsg(unsigned long * size){
    //get pid mapping for slot
    int i;
    int shm_slot=get_shm_slot();
    BUG_ON(shm_slot==-1);

    /*check if message is already present*/
    if(wait_event_timeout(wq, shinfo->message_count[shm_slot]>0,10000000) != 0 ){}

    /*read message*/
    char * slot_handle = ((char *)shinfo->receive_handle) + shinfo->metadata_size + shm_slot * shinfo->slot_size;
    stac();
    unsigned long head_offset = *((unsigned long *)slot_handle);
    clac();
    char * ptr = slot_handle+head_offset;
    stac();
    unsigned long msg_size = *((unsigned long *)ptr);
    clac();

    if(msg_size == -1){
        ptr = slot_handle+ 2 * sizeof(unsigned long);
        head_offset = 2 * sizeof(unsigned long);
        stac();
        msg_size = *((unsigned long *)ptr);
        clac();
    }
    ptr+=sizeof(unsigned long);
    *size = msg_size;
    void * msg = kmalloc(msg_size, GFP_KERNEL);
    stac();
    memcpy(msg,ptr,msg_size);
    clac();
    head_offset += sizeof(unsigned long) + msg_size;

    if(head_offset >= shinfo->slot_size)
        head_offset= 2 * sizeof(unsigned long);

    stac();
    *((unsigned long *)slot_handle)=head_offset;
    clac();

    mutex_lock(&(message_array_lock[shm_slot]));
    shinfo->message_count[shm_slot]-=1;
    mutex_unlock(&(message_array_lock[shm_slot]));

    return msg;
}

static ssize_t sandbox_shinfo_show(struct kobject *kobj,struct kobj_attribute *attr, char *buf){
        return sprintf(buf, "%d %d %d %d %lx %lu\n", shinfo->vmfd, shinfo->shmfd,
                                                     shinfo->host_eventfd, shinfo->guest_eventfd,
                                                     (unsigned long)shinfo->shmhandle, shinfo->size);
}

static ssize_t sandbox_shinfo_set(struct kobject *kobj, struct kobj_attribute *attr,const char *buf, size_t count){
        /*TODO sanity checks*/
        int i;
        if(count != sizeof(struct shm_information))
                  goto err_ret;
        memcpy(shinfo, buf, sizeof(struct shm_information));
        if(shinfo->host_eventfd < 0 || shinfo->guest_eventfd < 0)
               goto err_ret;

        for(i=0;i<max_shm_processes;i++){
          shinfo->pid_mapping[i]=-1;
        }
        for(i=0;i<max_shm_processes;i++){
          shinfo->message_count[i]=0;
        }
        shinfo->metadata_size = max_shm_processes;
        shinfo->send_handle = shinfo->shmhandle;
        shinfo->receive_handle = (shinfo->size / 2);
        shinfo->slot_size= ((shinfo->size - (shinfo->metadata_size * 2)) / 2) / max_shm_processes;
        return count;
err_ret:
        printk("Invalid sysfs args");
        return -EINVAL;
}
/* warning! need write-all permission so overriding check */

static struct kobj_attribute sandbox_shinfo_attribute = __ATTR(shinfo,0644,sandbox_shinfo_show, sandbox_shinfo_set);

static ssize_t sandbox_kickstart_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf){
        return sprintf(buf, "started = %d\n", atomic_read(&in_kernel));
}

static ssize_t sandbox_kickstart_set(struct kobject *kobj,struct kobj_attribute *attr, const char *buf, size_t count){
        atomic_set(&in_kernel, 1);
        handle_comm(shinfo, (char *)buf);
        return count;
}

static struct kobj_attribute sandbox_kickstart_attribute = __ATTR(kickstart, 0644, sandbox_kickstart_show, sandbox_kickstart_set);


static struct attribute *sandbox_attrs[] = {
        &sandbox_shinfo_attribute.attr,
        &sandbox_kickstart_attribute.attr,
        NULL,
};
static struct attribute_group sandbox_attr_group = {
        .attrs = sandbox_attrs,
        .name = "netsandbox",
};


int init_module(void){
        int err;
        struct shinfo *sh;
        printk(KERN_INFO "Hello kernel\n");

        shinfo = kmalloc(sizeof(struct shm_information), GFP_KERNEL);
        memset(shinfo, 0, sizeof(struct shm_information));

        err = sysfs_create_group (kernel_kobj, &sandbox_attr_group);
        if(unlikely(err))
                printk(KERN_INFO "sandbox: can't create sysfs\n");

        atomic_set(&in_kernel, 0);

        sh = init();
        if(!sh)
                goto cleanup_and_return;

        thread_st = kthread_run(thread_func, NULL, "mythread");
        if (!IS_ERR(thread_st)){
            printk("SANDBOX: Thread Created successfully\n");
        }
        else{
            printk("SANDBOX: Thread creation failed\n");
            thread_st = NULL;
        }
        return 0;

cleanup_and_return:
         sysfs_remove_group (kernel_kobj, &sandbox_attr_group);
         kfree(shinfo);
         return -EINVAL;

}

void cleanup_module(void){
        shutdown();
        sysfs_remove_group (kernel_kobj, &sandbox_attr_group);
        kfree(shinfo);
        if (thread_st){
           kthread_stop(thread_st);
           printk("SANDBOX: Thread stopped\n");
       	}
        printk(KERN_INFO "Goodbye kernel\n");
}

MODULE_AUTHOR("deba@cse.iitk.ac.in");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Host module for netstandbox");
