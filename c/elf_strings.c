/* elf_strings.c - 快速提取 .so 可读字符串与疑似密钥 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
int main(int argc,char **argv){
    if(argc<2){fprintf(stderr,"用法: %s <lib.so>\n",argv[0]);return 1;}
    FILE *f=fopen(argv[1],"rb"); if(!f){perror("open");return 1;}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *buf=malloc(n); fread(buf,1,n,f); fclose(f);
    if(n>=4&&buf[0]==0x7f&&!memcmp(buf+1,"ELF",3)) printf("[+] %s\n",buf[4]==2?"aarch64":"arm32");
    long i=0;
    while(i<n){
        if(isprint(buf[i])){
            long st=i; while(i<n&&isprint(buf[i]))i++; long len=i-st;
            if(len>=4&&len<=64){
                char *s=strndup((char*)(buf+st),len); int key=0;
                if(strstr(s,"key")||strstr(s,"Key")||strstr(s,"secret")||strstr(s,"aes")||strstr(s,"rc4")||strstr(s,"password")||strstr(s,"Java_")||strstr(s,"decrypt")) key=1;
                if(key) printf("  [KEY?] %s\n",s);
                free(s);
            }
        } else i++;
    }
    free(buf); return 0;
}
