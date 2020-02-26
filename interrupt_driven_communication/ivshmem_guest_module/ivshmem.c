#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/module.h>  // Needed by all modules

#include <linux/fs.h>      // Needed by filp
#include <asm/uaccess.h>
#include<linux/syscalls.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uio_driver.h>
#include <linux/io.h>

#define IntrStatus 0x04
#define IntrMask 0x00
#define IVPosition 0x08
#define Doorbell 0x0c

void __iomem *regs;
EXPORT_SYMBOL(regs);
struct ivshmem_kern_client;
struct ivshmem_info {
        struct ivshmem_kern_client *client;
        struct pci_dev *dev;
};



struct ivshmem_kern_client{
           void __iomem *internal_address_bar1;
           unsigned long address_bar1;
           unsigned long size_bar1;
           void __iomem *internal_address_bar2;
           unsigned long address_bar2;
           unsigned long size_bar2;
           long irq;
           unsigned long irq_flags;
           char name[16];
           void *priv;
};

#define max_shm_processes 5
#define SHM_SIZE 10000000
static DEFINE_MUTEX(notify_vm_lock);
struct mutex message_array_lock[max_shm_processes];
static DECLARE_WAIT_QUEUE_HEAD(wq);

struct shm_information{
                         void *shmhandle;
                         unsigned long size;
                         int pid_mapping[max_shm_processes];
                         int message_count[max_shm_processes];
                         void *receive_handle;
                         void *send_handle;
                         int metadata_size;
                         int slot_size;
};
static struct shm_information *shinfo = NULL;
int freeslot_for_new_process = -1;

// int send_some_message(struct ivshmem_kern_client *client)
// {
//    char buf[32];
//    printk(KERN_INFO "Interrupt received IVposition = %u\n", readl(client->internal_address_bar1 + IVPosition));
//    printk(KERN_INFO "data at shared = %s\n", (char *)regs);
//
//    sprintf(buf, "Length = %ld", strlen(regs));
//    memcpy(regs + 1024, buf, 32);
//
//    writel(0x10000, client->internal_address_bar1 + Doorbell);
//    return 0;
// }

int notify_host(int shm_slot, struct ivshmem_kern_client *client){
  *(((char *)shinfo->send_handle)+shm_slot)='1';
  writel(0x10000, client->internal_address_bar1 + Doorbell);

  return 0;
}

void put_msg_on_shm(int shm_slot, void * msg, unsigned long size){
    char * slot_handle = ((char *)shinfo->send_handle) + shinfo->metadata_size + shm_slot * shinfo->slot_size;
    unsigned long tail_offset = *(((unsigned long *)slot_handle)+1);
    char * ptr = slot_handle+tail_offset;
    if(shinfo->slot_size - tail_offset >= size + sizeof(unsigned long)){
        *((unsigned long *)ptr)=size;
        ptr += sizeof(unsigned long);
        memcpy((void *) ptr,msg,size);
        tail_offset=tail_offset+sizeof(unsigned long)+size;
        if(tail_offset >= shinfo->slot_size)
            tail_offset= 2 * sizeof(unsigned long);
    }
    else{
        *((unsigned long *)ptr)=-1;
        ptr = slot_handle + 2 * sizeof(unsigned long);
        *((unsigned long *)ptr)=size;
        ptr += sizeof(unsigned long);
        memcpy((void *) ptr,msg,size);
        tail_offset = 3 * sizeof(unsigned long)+size;
    }

    *(((unsigned long *)slot_handle)+1)=tail_offset;

    return;
}

int sendmsg(void * msg, unsigned long size){
    int i;
    int shm_slot=get_shm_slot();
    BUG_ON(shm_slot==-1);
    put_msg_on_shm(shm_slot,msg,size);

    mutex_lock(&notify_vm_lock);
    notify_vm(shm_slot);
    mutex_unlock(&notify_vm_lock);
    return 1;
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

//will be called by process
void * receivemsg(unsigned long * size){
    //get pid mapping for slot
    int i;
    int shm_slot=get_shm_slot();
    BUG_ON(shm_slot==-1);

    /*check if message is already present*/
    if(wait_event_timeout(wq, shinfo->message_count[shm_slot]>0,10000000) != 0 ){}

    /*read message*/
    char * slot_handle = ((char *)shinfo->receive_handle) + shinfo->metadata_size + shm_slot * shinfo->slot_size;
    unsigned long head_offset = *((unsigned long *)slot_handle);
    char * ptr = slot_handle+head_offset;
    unsigned long msg_size = *((unsigned long *)ptr);

    if(msg_size == -1){
        ptr = slot_handle+ 2 * sizeof(unsigned long);
        head_offset = 2 * sizeof(unsigned long);
        msg_size = *((unsigned long *)ptr);
    }
    ptr+=sizeof(unsigned long);

    void * msg;
    if(shm_slot==0){
      freeslot_for_new_process = *((int *)ptr);
      BUG_ON(freeslot_for_new_process<=0 || freeslot_for_new_process>=max_shm_processes);

      ptr += sizeof(int);
      *size = msg_size-sizeof(int);
      msg = kmalloc(msg_size - sizeof(int), GFP_KERNEL);
      memcpy(msg,ptr,msg_size - sizeof(int));
    }
    else{
      *size = msg_size;
      msg = kmalloc(msg_size, GFP_KERNEL);
      memcpy(msg,ptr,msg_size);
    }

    head_offset += sizeof(unsigned long) + msg_size;
    if(head_offset >= shinfo->slot_size)
        head_offset= 2 * sizeof(unsigned long);

    *((unsigned long *)slot_handle)=head_offset;

    mutex_lock(&(message_array_lock[shm_slot]));
    shinfo->message_count[shm_slot]-=1;
    mutex_unlock(&(message_array_lock[shm_slot]));

    return msg;
}


static irqreturn_t ivshmem_handler(int irq, void *arg){

        struct ivshmem_info *ivshmem_info;
        void __iomem *plx_intscr;
        struct ivshmem_kern_client *client = (struct ivshmem_kern_client *)arg;

        u32 val;

        ivshmem_info = client->priv;

        //send_some_message(client);
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

        //wake up process
        //bug possibility if handler stuck in lock
        mutex_lock(&(message_array_lock[shm_slot]));
        shinfo->message_count[shm_slot]+=1;
        mutex_unlock(&(message_array_lock[shm_slot]));
        wake_up(&wq);

        if (ivshmem_info->dev->msix_enabled)
                return IRQ_HANDLED;

        plx_intscr = client->internal_address_bar1 + IntrStatus;
        val = readl(plx_intscr);
        if (val == 0)
                return IRQ_NONE;

        return IRQ_HANDLED;
}

static int ivshmem_pci_probe(struct pci_dev *dev, const struct pci_device_id *id){

        struct ivshmem_kern_client *client;
        struct ivshmem_info *ivshmem_info;

        client = kzalloc(sizeof(struct ivshmem_kern_client), GFP_KERNEL);
        if (!client)
                return -ENOMEM;

        ivshmem_info = kzalloc(sizeof(struct ivshmem_info), GFP_KERNEL);
        if (!ivshmem_info) {
                kfree(client);
                return -ENOMEM;
        }
        client->priv = ivshmem_info;

        if (pci_enable_device(dev))
                goto out_free;

        if (pci_request_regions(dev, "ivshmem"))
                goto out_disable;

        client->address_bar1 = pci_resource_start(dev, 0);
        if (!client->address_bar1)
                goto out_release;

        client->size_bar1 = (pci_resource_len(dev, 0) + PAGE_SIZE - 1)
                & PAGE_MASK;
        client->internal_address_bar1 = pci_ioremap_bar(dev, 0);
        if (!client->internal_address_bar1)
                goto out_release;

        printk(KERN_INFO "calling pci_alloc with dev->irq = %d\n", dev->irq);

        if (1 > pci_alloc_irq_vectors(dev, 1, 1,
                                      PCI_IRQ_LEGACY | PCI_IRQ_MSIX))
        goto out_vector;


        client->address_bar2 = pci_resource_start(dev, 2);
        if (!client->address_bar2)
                goto out_unmap;

        client->size_bar2 = pci_resource_len(dev, 2);
        strcpy(client->name, "ivshmem");

        ivshmem_info->client = client;
        ivshmem_info->dev = dev;

        if (pci_irq_vector(dev, 0)) {
                client->irq = pci_irq_vector(dev, 0);
                client->irq_flags = IRQF_SHARED;
                if(request_irq(client->irq, &ivshmem_handler, client->irq_flags,
client->name, client))
                   dev_warn(&dev->dev, "Register IRQ failed\n");
        }else {
                dev_warn(&dev->dev, "No IRQ assigned to device: "
                         "no support for interrupts?\n");
        }
        pci_set_master(dev);


       if (!dev->msix_enabled)
                writel(0xffffffff, client->internal_address_bar1 + IntrMask);

        pci_set_drvdata(dev, ivshmem_info);
        printk("number %ld", client->address_bar2);
        regs = ioremap(client->address_bar2, client->size_bar2);

        shinfo = kmalloc(sizeof(struct shm_information), GFP_KERNEL);
        for(i=0;i<max_shm_processes;i++){
          shinfo->pid_mapping[i]=-1;
        }
        for(i=0;i<max_shm_processes;i++){
          shinfo->message_count[i]=0;
        }
        shinfo->shmhandle = (void *) regs;
        shinfo->size = SHM_SIZE;
        shinfo->metadata_size = max_shm_processes;
        shinfo->receive_handle = shinfo->shmhandle;
        shinfo->send_handle = (shinfo->size / 2);
        shinfo->slot_size= ((shinfo->size - (shinfo->metadata_size * 2)) / 2) / max_shm_processes;

        printk(KERN_INFO "ivshmem successfully loaded and initialized\n");
        //strncpy((char*)regs,"I m guest",9 );
        //iounmap(regs);

        return 0;
out_vector:
        pci_free_irq_vectors(dev);
out_unmap:
        printk("error 1");
        iounmap(client->internal_address_bar1);
out_release:
        printk("error2");
        pci_release_regions(dev);
out_disable:
        printk("error3");
        pci_disable_device(dev);
out_free:
        kfree(ivshmem_info);
        kfree(client);
        dev_warn(&dev->dev, "Device registration failed\n");

        return -ENODEV;
}

static void ivshmem_pci_remove(struct pci_dev *dev){
        struct ivshmem_info *ivshmem_info = pci_get_drvdata(dev);
        struct ivshmem_kern_client *client = ivshmem_info->client;

        pci_set_drvdata(dev, NULL);
        pci_free_irq_vectors(dev);
        iounmap(client->internal_address_bar1);
        pci_release_regions(dev);
        pci_disable_device(dev);
        kfree(client);
        kfree(ivshmem_info);
        //fh_exit();
}

static struct pci_device_id ivshmem_pci_ids[] = {
        {
                .vendor =       0x1af4,
                .device =       0x1110,
                .subvendor =    PCI_ANY_ID,
                .subdevice =    PCI_ANY_ID,
        },
        { 0, }
};

static struct pci_driver ivshmem_pci_driver = {
        .name = "uio_ivshmem",
        .id_table = ivshmem_pci_ids,
        .probe = ivshmem_pci_probe,
        .remove = ivshmem_pci_remove,
};

module_pci_driver(ivshmem_pci_driver);
MODULE_DEVICE_TABLE(pci, ivshmem_pci_ids);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cam Macdonell");
