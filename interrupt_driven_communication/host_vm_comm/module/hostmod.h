#ifndef __HOST_MOD_H__
#define __HOST_MOP_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/wait.h>

#define MSG_SIZE 0x4000
#define MSG_SHIFT 14
#define MAX_OPEN_FILES 64
#define MAX_PROCESS 64
#define MAX_FILENAME 128

struct ftrace_hook {
        const char *name;
        void *function;
        void *original;

        unsigned long address;
        struct ftrace_ops ops;
};

enum msg_status_t{
                   FREE=0,
                   USED,  /*Yet to be read*/
                   CONSUMED,
                   MAX_MSG_TYPE
};

enum msg_type_t{
                 OPEN_REQUEST = 0,
                 WRITE_REQUEST,
                 READ_REQUEST,
                 MMAP_REQUEST,
                 CLOSE_REQUEST,
                 LSEEK_REQUEST,
                 FSTAT_REQUEST,
                 EXECVE_REQUEST,
                 IOCTL_REQUEST
};



struct response{
        int length; //important in case of read/write 
        int type;
        char* buffer;
        int fd;
        size_t count;
        int pid;
};

struct open_req{
        int dfd;
        char filename[MAX_FILENAME];
        int flags;
        umode_t mode;
};

struct ioctl_req{
        unsigned int fd;
        unsigned int cmd;
        unsigned long arg;
};

struct msg_header
{
        u8 msg_status;
        u8 msg_type;
        u16 msg_length;
        int pid;
        int host_pid;
        int fd;
        size_t count;
        char msg[0];
} ;

struct open_file{
        int host_fd;
        int guest_fd;
        struct file * filp;
};

struct process_info{
        int pid;
        char wake_flag;
        struct response res;
        struct open_file open_files[MAX_OPEN_FILES];
        int ready;
};

struct shinfo{
                  void *mem;
                  unsigned long size;

                  u32 msg_size;
                  u32 num_descs;

                  void *send_ptr;
                  void *recv_ptr;
                 
                  wait_queue_head_t wq;
                  struct mutex send_lock;
                  struct mutex copy_lock;
                  spinlock_t process_lock;
 
                  struct process_info processes[MAX_PROCESS];
};

extern struct shinfo* init(void);
extern int shutdown(void);

extern int notify_vm(void);
extern int wait_for_vm_message(void);
extern void* get_shm_info(unsigned long *size);
 
#endif
