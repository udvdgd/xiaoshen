#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小神算法 - 测试语料生成器
生成约 1500 个文件: recoverable/noise/hard_enc/obfuscated。纯标准库。
"""
import os,sys,random,zlib,gzip,base64,json
random.seed(20261010)
ROOT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"test_corpus")
LUA=['local function main()\n  print("hello world")\n  return 0\nend\nmain()\n','local m=require("module")\nlocal x=m.init()\nfor i=1,10 do x=x+i end\nreturn x\n','function onTouch(x,y)\n  toast("t")\nend\n','local s="abcdef"\nprint(s:sub(2,4):upper())\n','while true do\n  if color()==0xffffff then click(100,200) end\n  sleep(500)\nend\n']
JS=['function main(){console.log("hi");return 1;}\nmain();','var config={host:"127.0.0.1",port:9000,ssl:false};','auto.waitFor();launchApp("x");setInterval(()=>{click(100,200)},1000);','let arr=[1,2,3,4].map(x=>x*2).filter(x=>x>3);console.log(arr);','"ui";ui.layout(<vertical><button text="go"/></vertical>);']
PY=['import os\ndef main():\n    print(os.getcwd())\nmain()\n','def enc(d,k):\n    return bytes(b^k[i%len(k)] for i,b in enumerate(d))\n','class Foo:\n    def __init__(self): self.x=1\n']
RC4K=[b"autojs",b"touchsprite",b"hamibot",b"2dxLua",b"tsprite",b"hyb1996",b"jzxc36g3PqBhmV44kI8"]
def rc4(data,key):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xFF; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for b in data:
        i=(i+1)&0xFF; j=(j+S[i])&0xFF; S[i],S[j]=S[j],S[i]; out.append(b^S[(S[i]+S[j])&0xFF])
    return bytes(out)
def write(rel,data):
    p=os.path.join(ROOT,rel); os.makedirs(os.path.dirname(p),exist_ok=True)
    open(p,"wb").write(data)
def gen_rec():
    for i in range(220):
        k=i%3
        src=(LUA if k==0 else JS if k==1 else PY)[ [i*7%len((LUA if k==0 else JS if k==1 else PY))] ][0] if False else random.choice(LUA if k==0 else JS if k==1 else PY).encode()
        ext=".lua" if k==0 else ".js" if k==1 else ".py"; m=i%6
        if m==0: b=base64.b64encode(src)
        elif m==1: b=zlib.compress(src)
        elif m==2: b=gzip.compress(src)
        elif m==3: b=rc4(src,random.choice(RC4K))
        elif m==4: b=base64.b64encode(zlib.compress(src))
        else: b=base64.b64encode(rc4(src,random.choice(RC4K)))
        write(f"recoverable/r{i:04d}{ext}",b)
def gen_noise():
    for i in range(520):
        k=i%6
        if k==0: b=bytes(random.getrandbits(8) for _ in range(random.randint(64,4096)))
        elif k==1: b=b"\x89PNG\r\n\x1a\n"+os.urandom(random.randint(128,1024))
        elif k==2: b=base64.b64encode(os.urandom(random.randint(20,200)))
        elif k==3: b=zlib.compress(os.urandom(random.randint(100,2000)))
        elif k==4:
            pat=bytes(random.getrandbits(8) for _ in range(random.randint(4,16))); b=pat*random.randint(20,200)
        else: b=b"\x7fELF"+os.urandom(random.randint(64,512))
        write(f"noise/n{i:04d}.bin",b)
def gen_hard():
    for i in range(300):
        k=i%4; src=random.choice(LUA+JS).encode(); rk=os.urandom(random.randint(8,24))
        if k==0: b=bytes(x^rk[j%len(rk)] for j,x in enumerate(src))
        elif k==1: b=rc4(src,rk)
        elif k==2:
            pad=16-len(src)%16; src2=src+bytes([pad])*pad; b=b"".join(rc4(src2[o:o+16],rk) for o in range(0,len(src2),16))
        else:
            b=rc4(src,rk); b=bytes(x^rk[j%len(rk)] for j,x in enumerate(b))
        write(f"hard_enc/h{i:04d}.dat",b)
NAMES=["_0x1a2b","_0x3f4c","_0x9e8d","_0x77aa","_0xdead","_0xbeef","_0xc0de","_0xf00d"]
def gen_obf():
    for i in range(520):
        k=i%3
        if k==0: b=("if false then\n _=9\nend\n"+random.choice(LUA)).encode(); ext=".lua"
        elif k==1: b=("if(1!==1){throw 1}\nvar "+",".join(NAMES[:5])+";\n"+random.choice(JS)).encode(); ext=".js"
        else:
            b=b"\x1bLua\x51\x00"+bytes(random.getrandbits(8) for _ in range(8))+random.choice(LUA).encode(); ext=".luac"
        write(f"obfuscated/o{i:04d}{ext}",b)
def main():
    import shutil
    if os.path.exists(ROOT): shutil.rmtree(ROOT)
    os.makedirs(ROOT)
    gen_rec(); gen_noise(); gen_hard(); gen_obf()
    c={"recoverable":220,"noise":520,"hard_enc":300,"obfuscated":520}
    man={"desc":"小神算法 测试语料","counts":c,"total":sum(c.values())}
    open(os.path.join(ROOT,"manifest.json"),"w").write(json.dumps(man,ensure_ascii=False,indent=2))
    print(json.dumps(man,ensure_ascii=False,indent=2))
if __name__=="__main__": main()
