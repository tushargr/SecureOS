/*
*  Kernel to kernel shared memory. Host side implementation. 
*/

#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<assert.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/eventfd.h>
#include<sys/un.h>
#include<string.h>

#define SHM_SIZE (1 << 20)
#define UNIX_SOCK_PATH "/tmp/ivshmem.sock"
#define VERSION 0
#define VMID 2

struct shm_information{
                         int vmfd;
                         int shmfd;
                         int host_eventfd;
                         int guest_eventfd;
                         void *shmhandle;
                         unsigned long size;
};


static int
send_one_msg(int sock_fd, long msg_t, int fd)
{
    int ret;
    struct msghdr msg;
    struct iovec iov[1];
    union {
        struct cmsghdr cmsg;
        char control[CMSG_SPACE(sizeof(int))];
    } msg_control;
    struct cmsghdr *cmsg;

    iov[0].iov_base = &msg_t;
    iov[0].iov_len = sizeof(msg_t);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    /* if fd is specified, add it in a cmsg */
    if (fd >= 0) {
        memset(&msg_control, 0, sizeof(msg_control));
        msg.msg_control = &msg_control;
        msg.msg_controllen = sizeof(msg_control);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    }

    ret = sendmsg(sock_fd, &msg, 0);
    if (ret <= 0) {
        return -1;
    }

    return 0;
}
void send_init_messages(struct shm_information *shm)
{
   char buf[128];
   unsigned long *msg = (unsigned long *)buf;

   *msg = VERSION;
   msg++;
   *msg = VMID;
   msg++;
   assert(send(shm->vmfd, buf, 16, 0) == 16);

   assert(send_one_msg(shm->vmfd, -1, shm->shmfd) == 0);
   assert(send_one_msg(shm->vmfd, 1, shm->host_eventfd) == 0);
   assert(send_one_msg(shm->vmfd, 2, shm->guest_eventfd) == 0);
   
}

/* 
  Create the server to catch the VM start and a default client in the host
  We only use two eventfds one for the host and other for the guest 
*/

void init_and_start_host(struct shm_information *shminfo)
{
    int sockfd, vmfd, ret;
    struct sockaddr_un sun;
    socklen_t unaddr_len;
   
    shminfo->shmfd = shm_open("ivshmem", O_CREAT | O_RDWR, S_IRWXU);

    assert(shminfo->shmfd >= 0);
    assert(!ftruncate(shminfo->shmfd, SHM_SIZE)); 

    shminfo->shmhandle = mmap(NULL, SHM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shminfo->shmfd, 0);
    assert(shminfo->shmhandle != MAP_FAILED);
    
    shminfo->host_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); 
    shminfo->guest_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    
    assert(shminfo->host_eventfd >=0 && shminfo->guest_eventfd >=0);
    shminfo->size = SHM_SIZE;
    
    /*
      Wait for the connection 
      XXX get rid of this nonsense when chardev is ready
     */
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(sockfd >= 0);

    sun.sun_family = AF_UNIX;
    ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s",
                   UNIX_SOCK_PATH);
    assert(ret == strlen(UNIX_SOCK_PATH));
    
    assert(bind(sockfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);

    assert(listen(sockfd, 5) == 0);

    unaddr_len = sizeof(sun);
    shminfo->vmfd = accept(sockfd, (struct sockaddr *)&sun, &unaddr_len);
    
    assert(shminfo->vmfd >= 0);
     
    send_init_messages(shminfo);

    close(shminfo->vmfd);
    close(sockfd);
    return; 
}

int main()
{
   int fd;
   struct shm_information shinfo;
   fd = open("/sys/kernel/netsandbox/shinfo", O_RDWR);
   assert(fd >= 0);
   
   init_and_start_host(&shinfo);


   assert(write(fd, &shinfo, sizeof(shinfo)) == sizeof(shinfo));
   close(fd);

   while(getchar()){
      fd = open("/sys/kernel/netsandbox/kickstart", O_RDWR);
      assert(fd >= 0);
      assert(write(fd, &shinfo, sizeof(shinfo)) == sizeof(shinfo));
      close(fd);
   }
    
#if 0
   /* Qemu sets the host eventfd to nonblocking. We don't want that */
   ctr = fcntl(shinfo.host_eventfd, F_GETFL);
   assert(ctr >= 0);
   printf("flags = %x\n", ctr);
   ctr = ctr & (~O_NONBLOCK); 
   assert(fcntl(shinfo.host_eventfd, F_SETFL, ctr) == 0);

   while(getchar()){
      for(ctr=1; ctr<=32; ++ctr){
          unsigned long kick = 1;
          memset(shinfo.shmhandle, 'A', ctr);
          memset(shinfo.shmhandle + ctr, 0, 1);
          assert(write(shinfo.guest_eventfd, &kick, sizeof(kick)) == sizeof(kick));

          if(read(shinfo.host_eventfd, &kick, sizeof(kick)) < 0){
              perror("read"); 
              assert(0);
          }
          //while(read(shinfo.host_eventfd, &kick, sizeof(kick)) < 0);
          //printf("Read value %ld\n", kick);
          printf("%s\n", (char *)shinfo.shmhandle + 1024);
      }
  }
#else
   
#endif
}
