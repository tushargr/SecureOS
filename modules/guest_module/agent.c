#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buf[1024];
    ssize_t len;
    int fd;

    fd = open("/sys/kernel/sysfs_kobject/vmmod_file", O_CREAT|O_RDWR|O_TRUNC);
    if (fd < 0) {
        perror("1");
        exit(1);
    }
    int sz = write(fd, "iamagent", strlen("iamagent"));
    


    while(1){
        lseek (fd, 0, SEEK_SET);
        len = read(fd, buf, sizeof(buf)-1);
        if (len < 0) {
            perror("3");
            exit(1);
        }
        if(len==0){
            sleep(5);
            continue;
        }
        else if(len>0){
            buf[len] = 0;
            printf("Forking new child\n");
            int pid = fork();
            if(pid==0){      //child
                close(3);
                int fdc = open("/sys/kernel/sysfs_kobject/vmmod_file", O_CREAT|O_RDWR|O_TRUNC);
                if (fdc < 0) {
                    perror("1");
                    exit(1);
                }
                int sz = write(fdc, "iamchild", strlen("iamchild"));
                close(fdc);         
                char *line[] = { "ssh", "tushargr@iitk.ac.in", 0 };
                execvp(line[0], line);
            }
            continue;
        }
    }
    close(fd);
    return 0;
}
