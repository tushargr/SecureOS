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
#include "hostmod.h"
struct shm_information{
                         int vmfd;
                         int shmfd;
                         int host_eventfd;
                         int guest_eventfd;
                         void *shmhandle;
                         unsigned long size;
};

atomic_t  in_kernel;

static struct shm_information *shinfo = NULL;

static struct file *g_efilp, *h_efilp;

int notify_vm(void)
{
  char *ptr;
  loff_t pos = 0;

  ptr = (char *)(shinfo->shmhandle +2048);
  *((unsigned long *) ptr) = 1;

  if(kernel_write(g_efilp, ptr, 8, &pos) != 8)
     return -EINVAL;
  return 0;
}

int wait_for_vm_message(void)
{
  char *ptr;
  struct fd f = fdget(shinfo->guest_eventfd);
  loff_t pos = 0;

  g_efilp = f.file;
  BUG_ON(!g_efilp);

  f  = fdget(shinfo->host_eventfd);
  h_efilp = f.file;

  BUG_ON(!h_efilp);
  h_efilp->f_flags &= ~O_NONBLOCK;

  ptr = (char *)(shinfo->shmhandle +2056);

  if(kernel_read(h_efilp, ptr, 8, &pos) != 8)
           return -EINVAL;
  return 0;

}

/*Returns the usable pointer part*/
void *get_shm_info(unsigned long *size)
{

   *size = shinfo->size - 4096;
   return (shinfo->shmhandle + 4096);
}

/*XXX Test implementation. */
int handle_comm(struct shm_information *shm, char *buf)
{
  struct file *g_efilp, *h_efilp;
  int ctr = 1;
  struct fd f = fdget(shm->guest_eventfd);

  g_efilp = f.file;
  BUG_ON(!g_efilp);

  printk(KERN_INFO "gefd flags = %x\n", g_efilp->f_flags);
  f  = fdget(shm->host_eventfd);
  h_efilp = f.file;
  printk(KERN_INFO "hefd flags = %x\n", h_efilp->f_flags);
  BUG_ON(!h_efilp);
  for(ctr=1; ctr<=16; ++ctr){
        loff_t pos = 0;
        stac();
        char *ptr = (char *)(shm->shmhandle +2048);
        *((unsigned long *) ptr) = 1;
        memset(shinfo->shmhandle, 'A', ctr);
        memset(shinfo->shmhandle + ctr, 0, 1);
        clac();
        g_efilp->f_flags &= ~O_NONBLOCK;
        //printk(KERN_INFO "write = %ld\n", kernel_write(g_efilp, ptr, 8, &pos));
        WARN_ON(kernel_write(g_efilp, ptr, 8, &pos) != 8);

        pos = 0;

        h_efilp->f_flags &= ~O_NONBLOCK;
        //printk(KERN_INFO "read =%ld\n", kernel_read(h_efilp, ptr, 8, &pos));
        WARN_ON(kernel_read(h_efilp, ptr, 8, &pos) != 8);
        stac();
        printk(KERN_INFO "%s\n", (char *)shinfo->shmhandle + 1024);
        clac();
  }

  return 0;
}

static ssize_t sandbox_shinfo_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%d %d %d %d %lx %lu\n", shinfo->vmfd, shinfo->shmfd,
                                                     shinfo->host_eventfd, shinfo->guest_eventfd,
                                                     (unsigned long)shinfo->shmhandle, shinfo->size);
}

static ssize_t sandbox_shinfo_set(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
        /*TODO sanity checks*/
        if(count != sizeof(struct shm_information))
                  goto err_ret;
        memcpy(shinfo, buf, sizeof(struct shm_information));
        if(shinfo->host_eventfd < 0 || shinfo->guest_eventfd < 0)
               goto err_ret;

        return count;
err_ret:
        printk("Invalid sysfs args");
        return -EINVAL;
}
/* warning! need write-all permission so overriding check */

static struct kobj_attribute sandbox_shinfo_attribute = __ATTR(shinfo,0644,sandbox_shinfo_show, sandbox_shinfo_set);

static ssize_t sandbox_kickstart_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "started = %d\n", atomic_read(&in_kernel));
}

static ssize_t sandbox_kickstart_set(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
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


int init_module(void)
{
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

        return 0;

cleanup_and_return:
         sysfs_remove_group (kernel_kobj, &sandbox_attr_group);
         kfree(shinfo);
         return -EINVAL;

}

void cleanup_module(void)
{
        shutdown();
        sysfs_remove_group (kernel_kobj, &sandbox_attr_group);
        kfree(shinfo);
        printk(KERN_INFO "Goodbye kernel\n");
}

MODULE_AUTHOR("deba@cse.iitk.ac.in");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Host module for netstandbox");
