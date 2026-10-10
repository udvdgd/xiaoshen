/* xor_brute.c - 高性能单字节 XOR 爆破 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *KW[]={"function","var ","import","local ","//","#","require","return","if ","for ",NULL};
int main(int argc,char **argv){
    if(argc<2){fprintf(stderr,"用法: %s <文件>\n",argv[0]);return 1;}
    FILE *f=fopen(argv[1],"rb"); if(!f){perror("open");return 1;}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *buf=malloc(n); fread(buf,1,n,f); fclose(f);
    int bk=0,bs=0;
    for(int k=1;k<256;k++){
        int score=0; long lim=n<600?n:600;
        for(long i=0;i<lim;i++){
            unsigned char c=buf[i]^k;
            for(int w=0;KW[w];w++){int l=strlen(KW[w]); if(i+l<=lim&&!memcmp(buf+i,KW[w],l)) score++;}
        }
        if(score>bs){bs=score;bk=k;}
    }
    printf("XOR key=0x%02X score=%d\n",bk,bs);
    if(bs>0) for(long i=0;i<n;i++) putchar(buf[i]^bk);
    free(buf); return 0;
}
