#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""万能自动解密器: 试遍所有方案取评分最高"""
from py.core.decryptors import RC4, XOREngine, ChaCha20, SM4, XXTEA, Encoding, Compression

MEGA_KEYS=[b"123456",b"password",b"admin",b"root",b"test",b"key",b"12345678",b"abcdef",b"autojs",b"auto.js",b"hyb1996",b"touchsprite",b"tsprite",b"hamibot",b"qmacro",b"game",b"cheat",b"hack",b"script",b"android",b"xiaoshen",b"vip",b"pro",b"0123456789abcdef",b"abcdef0123456789",b"1234567890123456",b"deadbeefdeadbeef",b"0123456789abcdef0123456789abcdef"]
NONCES=[b"\x00"*12,b"\x01"*12,b"autojs"+b"\x00"*6,b"script123456"]

class UniversalDecryptor:
    @staticmethod
    def score(data):
        if len(data)<4: return -999
        head=data[:600]
        kws=[b"function",b"var ",b"let ",b"import",b"local ",b"//",b"require(",b"console.",b"print(",b"return ",b"if ",b"for ",b"device.",b"toast(",b"auto.",b"#!/",b"module.",b"exports."]
        s=sum(head.count(k)*10 for k in kws)
        pr=sum(1 for b in head if 0x20<=b<=0x7e or b in (9,10,13))
        s+=(pr*3)//max(1,len(head)); return s
    @staticmethod
    def try_all(data,max_layers=6):
        best={"data":data,"score":UniversalDecryptor.score(data),"method":"raw","layers":[]}; cands=[]
        for name,fn in [("base64",Encoding.b64),("base64url",Encoding.b64url),("base32",Encoding.b32),("hex",Encoding.hex),("rot13",Encoding.rot13),("reverse",Encoding.reverse)]:
            try:
                o=fn(data)
                if o!=data and len(o)>0: cands.append((name,o))
            except: pass
        for name,fn in [("zlib",Compression.zlib),("gzip",Compression.gzip)]:
            try:
                o=fn(data)
                if o!=data: cands.append((name,o))
            except: pass
        for k in range(1,256): cands.append((f"xor{k}",bytes(b^k for b in data)))
        for key in MEGA_KEYS:
            try: cands.append((f"rc4",RC4.crypt(data,key)))
            except: pass
            try: cands.append((f"xork",XOREngine.multi_byte(data,key)))
            except: pass
        for key in MEGA_KEYS:
            if len(key) in (16,32):
                for nonce in NONCES:
                    try: cands.append(("chacha",ChaCha20.decrypt(key.ljust(32,b'\x00')[:32],nonce,data)))
                    except: pass
            if len(key)>=16:
                try: cands.append(("sm4",SM4.decrypt(data,key[:16])))
                except: pass
            try: cands.append(("xxtea",XXTEA.decrypt(data,key.ljust(16,b'\x00')[:16])))
            except: pass
        for name,o in cands:
            s=UniversalDecryptor.score(o)
            if s>best["score"]: best={"data":o,"score":s,"method":name,"layers":best["layers"]+[name]}
        if best["score"]>50 and len(best["layers"])<max_layers:
            sub=UniversalDecryptor.try_all(best["data"],max_layers)
            if sub["score"]>best["score"]+5:
                sub["layers"]=best["layers"]+sub["layers"]; return sub
        return best

def main():
    import sys
    data=open(sys.argv[1],'rb').read(); r=UniversalDecryptor.try_all(data)
    print("方法",r["method"],"链",'->'.join(r["layers"]),"分",r["score"])
    print(r['data'][:500].decode('utf-8','ignore'))

if __name__=="__main__": main()
