#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, base64, random

def _rc4_crypt(data,key):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])%256; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for byte in data:
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        out.append(byte^S[(S[i]+S[j])%256])
    return bytes(out)

JUNK_HEAD=16; JUNK_TAIL=8

def _xshen_crypt(data,key):
    S=list(range(256)); j=0; klen=len(key)
    for i in range(256):
        j=(j+S[i]+key[i%klen]+(i*7))%256; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0; n=0
    for byte in data:
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        ks=S[(S[i]+S[j])%256]^(((n+1)*31+7)&0xFF)
        out.append(byte^ks); n+=1
    return bytes(out)

def _to16(b): return "".join("\\x%02x"%x for x in b)

def encrypt_lua(source):
    raw=source.encode("utf-8")
    key=bytes(random.randint(1,255) for _ in range(16))
    body=_xshen_crypt(raw,key)
    jh=bytes(random.randint(0,255) for _ in range(JUNK_HEAD))
    jt=bytes(random.randint(0,255) for _ in range(JUNK_TAIL))
    blob=jh+body+jt
    p1=bytes(random.randint(0,255) for _ in range(16))
    p2=bytes(random.randint(0,255) for _ in range(16))
    p3=bytes(a^b^c for a,b,c in zip(key,p1,p2))
    k1,k2,k3=_to16(p1),_to16(p2),_to16(p3)
    def vn(n=6): return "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))
    P1,P2,P3,D,K=vn(),vn(),vn(),vn(),vn(); fn,out,dec,f=vn(8),vn(5),vn(4),vn(2)
    h,t=JUNK_HEAD,JUNK_TAIL; blob16=_to16(blob)
    return f'''-- 小神算法 企业级加密 (自研多层)
local {P1}="{k1}"
local {P2}="{k2}"
local {P3}="{k3}"
local {D}="{blob16}"
local H,T={h},{t}
local function {fn}(data,key)
  local S={{}}; for i=0,255 do S[i]=i end
  local j=0
  for i=0,255 do
    j=(j+S[i]+key:byte((i%#key)+1)+(i*7))%256; S[i],S[j]=S[j],S[i]
  end
  local {out}={{}}; local a=0; local b=0; local n=0
  for p=1,#data do
    a=(a+1)%256; b=(b+S[a])%256; S[a],S[b]=S[b],S[a]
    local ks=S[(S[a]+S[b])%256]~(((n+1)*31+7)%256)
    {out}[p]=string.char(data:byte(p)~ks); n=n+1
  end
  return table.concat({out})
end
local {K}=""
for i=1,16 do {K}={K}..string.char({P1}:byte(i)~{P2}:byte(i)~{P3}:byte(i)) end
local real={D}:sub(H+1,#{D}-T)
local {dec}={fn}(real,{K})
local {f}=assert(load({dec}))
{f}()
'''

def encrypt_js(source):
    raw=source.encode("utf-8"); key=bytes(random.randint(1,255) for _ in range(8))
    ct=bytes(b^key[i%len(key)] for i,b in enumerate(raw))
    b64=base64.b64encode(ct).decode(); karr=",".join(str(x) for x in key)
    return f'''// 小神算法 企业级加密
(function(){{
 var D="{b64}"; var K=[{karr}];
 var raw=atob(D),out="";
 for(var i=0;i<raw.length;i++)out+=String.fromCharCode(raw.charCodeAt(i)^K[i%K.length]);
 eval(out);
}})();
'''

def encrypt_py(source):
    raw=source.encode("utf-8"); key=bytes(random.randint(1,255) for _ in range(8))
    ct=bytes(b^key[i%len(key)] for i,b in enumerate(raw))
    b64=base64.b64encode(ct).decode(); karr=",".join(str(x) for x in key)
    return f'''# 小神算法 企业级加密
import base64
D="{b64}"; K=[{karr}]
raw=base64.b64decode(D)
exec(bytes(b^K[i%len(K)] for i,b in enumerate(raw)))
'''

def _lcg(state):
    state=(state*48271)%2147483647; return state%256,state

def _hide_fragments(master):
    f1=bytes(random.randint(0,255) for _ in range(4))
    f2=bytes(random.randint(0,255) for _ in range(4))
    f3=bytes(a^b^c for a,b,c in zip(master,f1,f2))
    pile=[]
    for r in f1: pile.append(r); pile.append(random.randint(0,255))
    h1=" ".join(str(x) for x in pile)
    h2="".join(format(b,"08b") for b in f2)
    h3="".join(chr(b) for b in f3)[::-1]
    return h1,h2,h3

def encrypt_sh(source,layers=50):
    raw=list(source.encode("utf-8"))
    master=bytes(random.randint(1,255) for _ in range(4))
    seed=int.from_bytes(master,"big")%2147483647 or 1
    state=seed; data=raw[:]
    for _ in range(layers):
        ks=[]
        for _ in range(len(data)): k,state=_lcg(state); ks.append(k)
        op,state=_lcg(state); op%=5
        if op==0: data=[b^ks[i] for i,b in enumerate(data)]
        elif op==1: data=[(b+ks[i])&0xFF for i,b in enumerate(data)]
        elif op==2: data=[((b<<(ks[i]%8))|(b>>(8-ks[i]%8)))&0xFF for i,b in enumerate(data)]
        elif op==3: data=[((b<<4)|(b>>4))&0xFF for b in data]
        else:
            out=[]
            for i in range(0,len(data),16): out+=data[i:i+16][::-1]
            data=out
    b64=base64.b64encode(bytes(data)).decode()
    clen,csum=len(raw),sum(raw)%65536
    h1,h2,h3=_hide_fragments(master)
    awk='''function bxor(a,b,  r,p,ba,bb){
 r=0; p=1
 while(a>0 || b>0){ ba=a%2; bb=b%2; if(ba!=bb)r+=p; a=int(a/2); b=int(b/2); p*=2 }
 return r
}
function lcg(  s){ s=(SEED*48271)%2147483647; SEED=s; return s%256 }
BEGIN { N=0; for(z=0;z<256;z++){ oc=sprintf("%c",z); ORD[oc]=z } }
{ for(i=1;i<=NF;i++){ N++; arr[N]=$i+0 } }
END {
 m=split(P1,q," "); z=0
 for(i=1;i<=m;i+=2){ z++; A[z]=q[i]+0 }
 for(i=0;i<4;i++){ v=0; for(j=1;j<=8;j++) v=v*2+(substr(P2,i*8+j,1)+0); B[i+1]=v }
 L3=length(P3); SEED=0
 for(i=1;i<=4;i++){ ch=substr(P3,L3-i+1,1); rv=bxor(bxor(A[i],B[i]),ORD[ch]); SEED=SEED*256+rv }
 SEED=SEED%2147483647; if(SEED==0)SEED=1
 for(L=NL;L>=1;L--){
  S2=SEED
  for(x=1;x<L;x++){ for(i=1;i<=N;i++) lcg(); lcg() }
  for(i=1;i<=N;i++) K[i]=lcg()
  o=lcg()%5
  if(o==0){ for(i=1;i<=N;i++) arr[i]=bxor(arr[i],K[i]) }
  else if(o==1){ for(i=1;i<=N;i++) arr[i]=(arr[i]-K[i]+256)%256 }
  else if(o==2){ for(i=1;i<=N;i++){ r=K[i]%8; arr[i]=(int(arr[i]/(2^r))+int(arr[i]*(2^(8-r))))%256 } }
  else if(o==3){ for(i=1;i<=N;i++) arr[i]=int(arr[i]/16)+(arr[i]%16)*16 }
  else { for(b=1;b<=N;b+=16){ j=b; k=b+15; if(k>N)k=N; while(j<k){ t=arr[j]; arr[j]=arr[k]; arr[k]=t; j++; k-- } } }
  SEED=S2
 }
 chk=0; for(i=1;i<=N;i++) chk=(chk+arr[i])%65536
 if(N!=CLEN||chk!=CSUM){ print "integrity check failed">"/dev/stderr"; exit 1 }
 for(i=1;i<=N;i++) printf "%c",arr[i]
}'''
    return f'''#!/system/bin/sh
B64="{b64}"
P1="{h1}"
P2="{h2}"
P3="{h3}"
NL={layers}
AWK=./.xsn.awk
cat > $AWK <<'AWKEOF'
{awk}
AWKEOF
echo "$B64" | base64 -d | od -An -v -tu1 | awk -v P1="$P1" -v P2="$P2" -v P3="$P3" -v NL=$NL -v CLEN={clen} -v CSUM={csum} -f $AWK | sh
rm -f $AWK
'''

def encrypt_file(path):
    ext=os.path.splitext(path)[1].lower()
    src=open(path,"r",encoding="utf-8",errors="replace").read()
    if ext==".lua": return encrypt_lua(src),"Lua"
    if ext in (".js",".ts"): return encrypt_js(src),"JS"
    if ext==".py": return encrypt_py(src),"Python"
    if ext in (".sh",".bash",""): return encrypt_sh(src),"Shell"
    return encrypt_lua(src),"Lua"
