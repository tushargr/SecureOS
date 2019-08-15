#include<stdio.h> 
#include<string.h>
#include <unistd.h>
#include<stdio.h>
int main(){
        //char ssh_arg[256];    
        printf("8d42c43449108789f51476ac8a0d386334cae1360fa9f9c3377073e8e4792653\n");
        char ar[32];

        scanf( "%s" , ar);
        int pid = fork();
        if(pid==0){
        	char *line[] = { "ssh", ar, 0 };

			execvp(line[0], line);
        }
        return 0;
}
