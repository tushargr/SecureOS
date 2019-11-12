#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>



int main(){    
    // close(3);
    // int fdc = open("/sys/kernel/sysfs_kobject/vmmod_file", O_CREAT|O_RDWR|O_TRUNC);
    // if (fdc < 0) {
    //     perror("1");
    //     exit(1);
    // }
    // int sz = write(fdc, "iamchild", strlen("iamchild"));
    // close(fdc); 
    int fd = open("/home/lib", O_RDONLY, 0);
    assert(fd != -1);


    struct stat buf;
    fstat(fd, &buf);
    size_t fsize = buf.st_size;
    printf("size of file=%d\n",fsize);

    void* mmappedData = mmap(NULL, fsize, PROT_READ, MAP_SHARED , fd, 0);
    if(mmappedData == MAP_FAILED){
        perror("mmap");
        assert(0);
    }
    //assert(mmappedData != MAP_FAILED);
    write(1, mmappedData, fsize);
    int rc = munmap(mmappedData, fsize);
    assert(rc == 0);
    close(fd);

   return 0;
}