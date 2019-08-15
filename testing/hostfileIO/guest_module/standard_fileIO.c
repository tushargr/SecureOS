#include<stdio.h> 
#include<stdlib.h> 
#include<string.h>
#include <unistd.h>
#include<stdio.h> 
#include<fcntl.h> 
#include<errno.h>
#include <sys/time.h>

int main(){
        //char ssh_arg[256];    
        printf("8d42c43449108789f51476ac8a0d386334cae1360fa9f9c3377073e8e4792653\n");
        int pid = fork();
        if(pid==0){
                printf("c6235874094907ec06e1d8474926a23190026126d9c175e7f6b07bdc206e8df9\n");
                struct timeval tval_before, tval_after, tval_result;

                gettimeofday(&tval_before, NULL);
                int fd = open("/tmp/file1.txt", O_WRONLY | O_CREAT | O_TRUNC);
                gettimeofday(&tval_after, NULL);
                printf(" open start sec=%ld usec=%ld , end = sec=%ld usec=%ld\n",tval_before.tv_sec,tval_before.tv_usec,tval_after.tv_sec,tval_after.tv_usec);
                



                gettimeofday(&tval_before, NULL);
                char *c = (char *) calloc(1001, sizeof(char));
                int sz = read(fd, c, 1000); 
                printf("content = %s\n", c);
                gettimeofday(&tval_after, NULL);
                printf(" read start sec=%ld usec=%ld , end = sec=%ld usec=%ld\n",tval_before.tv_sec,tval_before.tv_usec,tval_after.tv_sec,tval_after.tv_usec);
                


                gettimeofday(&tval_before, NULL);
                sz = write(fd, "hello\n", strlen("hello\n"));
                gettimeofday(&tval_after, NULL);
                printf(" write start sec=%ld usec=%ld , end = sec=%ld usec=%ld\n",tval_before.tv_sec,tval_before.tv_usec,tval_after.tv_sec,tval_after.tv_usec);
        }
        return 0;
}