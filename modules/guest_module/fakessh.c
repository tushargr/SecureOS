#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(){
    int fd;
    fd = open("/sys/kernel/sysfs_kobject/sysfs_file", O_CREAT|O_RDWR|O_TRUNC);
    if (fd < 0) {
        perror("1");
        exit(1);
    }
    int sz = write(fd, "iamchild", strlen("iamchild"));
    close(fd);

	char file[128] = "/home/";
    char arg[64];
    printf("Please enter the name of secret file you want\n");
    scanf("%s",arg);
    strcat(file,arg);
    fd = open(file, O_RDWR|O_CREAT,0666);
    if(fd < 0)
        exit(-1);

    printf("Please enter the message you want to put\n");
    scanf("%s",arg);
    write(fd,arg,strlen(arg));
    printf("Thanks for using the app\n");
    close(fd);
    return 0;
}