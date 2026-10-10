/* smart_brute.c - 渐进式智能爆破内核 (C 高速版)
 *  ./smart_brute rc4|xor file [max_len]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static const char *KW[]={"function","var ","let ","const","import","local ","require","return ","if (","for (","while","console.","print(","toast(","device.","auto.","//","/*","#include","module.",NULL};

static int score(const unsigned char *d,long n){
    if(n<4)return 0;
    long lim=n<500?n:500; int sc=0;
    for(int w=0;KW[w];w++){int l=strlen(KW[w]); for(long i=0;i+l<=lim;i++) if(!memcmp(d+i,KW[w],l))sc+=10;}
    int pr=0; for(long i=0;i<lim;i++) if(d[i]>=0x20&&d[i]<=0x7e)pr++;
    sc+=(pr*10)/lim; return sc;
}

static void rc4(const unsigned char *key,int kl,const unsigned char *in,unsigned char *out,long n){
    uint8_t S[256]; for(int i=0;i<256;i++)S[i]=i; int j=0;
    for(int i=0;i<256;i++){j=(j+S[i]+key[i%kl])&0xFF; uint8_t t=S[i];S[i]=S[j];S[j]=t;}
    int a=0,b=0;
    for(long i=0;i<n;i++){a=(a+1)&0xFF;b=(b+S[a])&0xFF;uint8_t t=S[a];S[a]=S[b];S[b]=t; out[i]=in[i]^S[(S[a]+S[b])&0xFF];}
}

static const char *CHARSETS[]={"0123456789","abcdefghijklmnopqrstuvwxyz","ABCDEFGHIJKLMNOPQRSTUVWXYZ","0123456789abcdef","abcdefghijklmnopqrstuvwxyz0123456789","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",NULL};
static const int ORDER[]={0,1,4,3,5,6,2};
#define NC 7
static const char *WORDS[]={"123456","password","admin","autojs","script","touchsprite","hamibot","qmacro","key","test","root","abc123","game","cheat","hack","android","xiaoshen","auto","pro","vip","admin123",NULL};

static unsigned char *g_buf; static long g_len; static int g_bs=0; static char g_key[256]; static long g_tried=0;

static void try_rc4(const char *key,int kl){
    unsigned char *out=malloc(g_len); rc((const unsigned char*)key,kl,g_buf,out,g_len);
    int s=score(out,g_len);
    if(s>g_bs){g_bs=s; memcpy(g_key,key,kl); g_key[kl]=0; printf("\r[*] %ld key=%.*s s=%d",g_tried,kl,key,s); fflush(stdout);}
    free(out);
}
static void try_xor(const char *key,int kl){
    long n=g_len<500?g_len:500; unsigned char out[500];
    for(long i=0;i<n;i++) out[i]=g_buf[i]^((unsigned char)key[i%kl]);
    int s=score(out,n);
    if(s>g_bs){g_bs=s; memcpy(g_key,key,kl); g_key[kl]=0; printf("\r[*] %ld XOR key=%.*s s=%d",g_tried,kl,key,s); fflush(stdout);}
}
static void rec(const char *cs,int csl,char *b,int pos,int max,void(*fn)(const char*,int)){
    if(pos>0){fn(b,pos); g_tried++; if(g_bs>=50)return;}
    if(pos>=max)return;
    for(int i=0;i<csl;i++){b[pos]=cs[i]; rec(cs,csl,b,pos+1,max,fn); if(g_bs>=50)return;}
}
int main(int argc,char **argv){
    if(argc<3){fprintf(stderr,"用法: %s rc4|xor file [max=6]\n",argv[0]);return 1;}
    const char *mode=argv[1],*file=argv[2]; int max=argc>3?atoi(argv[3]):6;
    FILE *f=fopen(file,"rb"); if(!f){perror("open");return 1;}
    fseek(f,0,SEEK_END); g_len=ftell(f); fseek(f,0,SEEK_SET); g_buf=malloc(g_len); fread(g_buf,1,g_len,f); fclose(f);
    printf("=== smart brute: %s (%ldB) ===\n",mode,g_len);
    time_t t0=time(NULL);
    printf("[Phase 1] words\n");
    for(int w=0;WORDS[w];w++){int kl=strlen(WORDS[w]); if(!strcmp(mode,"rc4"))try_rc4(WORDS[w],kl); else try_xor(WORDS[w],kl); g_tried++;}
    char b[256];
    for(int ci=0;ci<NC;ci++){
        const char *cs=CHARSETS[ORDER[ci]]; int csl=strlen(cs);
        for(int len=1;len<=max;len++){ if(g_bs>=50)goto done; rec(cs,csl,b,0,len,!strcmp(mode,"rc4")?try_rc4:try_xor);}
    }
done:;
    time_t t1=time(NULL);
    printf("\n tried=%ld time=%lds best=\"%s\" score=%d\n",g_tried,(long)(t1-t0),g_key,g_bs);
    if(g_bs>=20){
        unsigned char *out=malloc(g_len);
        if(!strcmp(mode,"rc4"))rc((unsigned char*)g_key,strlen(g_key),g_buf,out,g_len);
        else for(long i=0;i<g_len;i++)out[i]=g_buf[i]^((unsigned char)g_key[i%strlen(g_key)]);
        fwrite(out,1,g_len<2000?g_len:2000,stdout); free(out);
    }
    free(g_buf); return g_bs>=20?0:1;
}
