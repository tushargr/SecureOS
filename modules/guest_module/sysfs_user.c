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

    fd = open("/sys/kernel/kobject_example/foo", O_CREAT|O_RDWR|O_TRUNC);
    if (fd < 0) {
        perror("cannot open sysfs file");
        exit(1);
    }
    int sz = write(fd, "hello geeks", strlen("hello geeks"));
    close(fd);



    fd = open("foo", O_RDONLY);
    if (fd < 0) {
        perror("cannot open sysfs file");
        exit(1);
    }

    len = read(fd, buf, sizeof(buf)-1);
    if (len < 0) {
       perror("unable to read from sysfs file");
       exit(1);
    }
    printf("%ld\n",len);
    buf[len] = 0;
    printf("Data : %s\n", buf);

    close(fd);
    return 0;
}
