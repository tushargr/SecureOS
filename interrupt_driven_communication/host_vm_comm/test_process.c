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

int main(){

  int fd = open("/sys/kernel/netsandbox/kickstart", O_RDWR);
  assert(fd >= 0);
  assert(write(fd, "a", 1) == 1);
  close(fd);

  return 0;
}
