/* rc4_crack.c - RC4 常见字典爆破 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *DICT[]={"123456","admin","autojs","script","touchsprite","hamibot","qmacro","key","xiaoshen","password","000000","888888","12345678","abcdef","qwerty","root","test","android","auto.js","hyb1996",NULL};
static int looks_text(const unsigned char *d,long n){
    int hits=0; const char *kw[]={"function","var ","import","local ","//","require",NULL};
    long lim=n<400?n:400;
    for(int w=0;kw[w];w++){int l=strlen(kw[w]); for(long i=0;i+l<=lim;i++) if(!memcmp(d+i,kw[w],l)) hits++;}
    return hits;
}
int main(int argc,char **argv){
    if(argc<2){fprintf(stderr,"用法: %s <文件>\n",argv[0]);return 1;}
    FILE *f=fopen(argv[1],"rb"); fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *buf=malloc(n); fread(buf,1,n,f); fclose(f);
    for(int w=0;DICT[w];w++){
        const char *key=DICT[w]; int kl=strlen(key); unsigned char S[256];
        for(int i=0;i<256;i++)S[i]=i;
        int j=0;
        for(int i=0;i<256;i++){j=(j+S[i]+key[i%kl])&0xFF; unsigned char t=S[i];S[i]=S[j];S[j]=t;}
        unsigned char *out=malloc(n); int a=0,b=0;
        for(long i=0;i<n;i++){
            a=(a+1)&0xFF; b=(b+S[a])&0xFF; unsigned char t=S[a];S[a]=S[b];S[b]=t;
            out[i]=buf[i]^S[(S[a]+S[b])&0xFF];
        }
        int sc=looks_text(out,n);
        if(sc>0){printf("[命中] key=%s score=%d\n",key,sc); fwrite(out,1,n,stdout); free(out);free(buf); return 0;}
        free(out);
    }
    printf("[未命中]\n"); free(buf); return 1;
}
