#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
小神算法 · 自研独家算法集 (XShen Proprietary Cipher Suite) v1.0
四个自研原语组合: XSKeystream(非线性流) / XSFeistel(64位Feistel-CBC) / XSNested(随机多层嵌套) / XSKDF(密钥扩展)
顶层 XSCipher.encrypt/decrypt 串联并附三重完整性校验。
定位: 自研对称变换+强混淆; 免填密钥自解脚本内部仍含还原材料, 属强混淆。仅用于保护自有/授权内容。
"""
import os,struct
MASK32=0xFFFFFFFF; MASK64=0xFFFFFFFFFFFFFFFF
def _rotl32(v,n):
    n&=31; return ((v<<n)|(v>>(32-n)))&MASK32 if n else v&MASK32
def _rotr32(v,n):
    n&=31; return ((v>>n)|(v<<(32-n)))&MASK32 if n else v&MASK32
def _rotl64(v,n):
    n&=63; return ((v<<n)|(v>>(64-n)))&MASK64 if n else v&MASK64

class XSKDF:
    @staticmethod
    def _mix(state,word,r):
        state=(state^word)&MASK32
        state=(state*0x45D9F3B+0x9E3779B9)&MASK32
        state^=_rotl32(state,(r*7)&31)
        state=(state+_rotl32(word|1,(r*13)&31))&MASK32
        return state
    @classmethod
    def expand(cls,key,count):
        if not key: key=b"\x00"
        padded=key+b"\x00"*((-len(key))%4)
        words=list(struct.unpack("<%dI"%(len(padded)//4),padded))
        reg=[0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,0xA4093822,0x299F31D0,0x082EFA98,0xEC4E6C89]
        for i in range(8): reg[i]^=words[i%len(words)]
        sub=[]
        for r in range(count):
            t=reg[r%8]; t=cls._mix(t,words[r%len(words)],r); t=cls._mix(t,reg[(r+3)%8],r+1)
            reg[r%8]=t; sub.append(t)
        return sub
    @classmethod
    def byte_seed(cls,key):
        return b"".join(struct.pack("<I",w) for w in cls.expand(key,64))

class XSKeystream:
    @staticmethod
    def _ks_byte(S,a,b,acc,n):
        a=(a+1)&0xFF
        b=(b+S[a]+((acc>>(n&31))&0xFF)+n)&0xFF
        S[a],S[b]=S[b],S[a]
        t=S[(S[a]+S[b])&0xFF]
        acc=(_rotl64(acc^(t*0x9E3779B185EBCA87&MASK64),(17+(n&7))&63)+((n+1)*0x100000001B3))&MASK64
        ks=t^(acc&0xFF)^((acc>>23)&0xFF)^((acc>>40)&0xFF)
        return a,b,acc,ks&0xFF
    @classmethod
    def crypt(cls,data,key):
        seed=XSKDF.byte_seed(key); S=list(range(256)); j=0
        for i in range(256):
            j=(j+S[i]+seed[i]+((i*31)&0xFF))&0xFF; S[i],S[j]=S[j],S[i]
        for i in range(256):
            j=(j+S[i]+seed[(i+128)&0xFF]+(seed[i]&0x0F))&0xFF; S[i],S[j]=S[j],S[i]
        a=b=0
        acc=(struct.unpack("<Q",seed[:8])[0]^struct.unpack("<Q",seed[8:16])[0])&MASK64
        if acc==0: acc=0x9E3779B97F4A7C15
        out=bytearray(len(data))
        for n,byte in enumerate(data):
            a,b,acc,ks=cls._ks_byte(S,a,b,acc,n); out[n]=byte^ks
        return bytes(out)

class XSFeistel:
    ROUNDS=16; BLOCK=8
    @staticmethod
    def _F(h,sk,r):
        x=(h^sk)&MASK32; x=(x*0x85EBCA6B+0xC2B2AE35)&MASK32
        x^=_rotl32(x,(x&15)^(r&15))
        x=(x+_rotl32(sk|1,(r*5)&31))&MASK32; x^=_rotl32(x,11)
        return x
    @classmethod
    def _enc_block(cls,b,sub):
        L,R=struct.unpack("<II",b)
        for r in range(cls.ROUNDS): L,R=R,(L^cls._F(R,sub[r],r))&MASK32
        return struct.pack("<II",L,R)
    @classmethod
    def _dec_block(cls,b,sub):
        L,R=struct.unpack("<II",b)
        for r in range(cls.ROUNDS-1,-1,-1): L,R=(R^cls._F(L,sub[r],r))&MASK32,L
        return struct.pack("<II",L,R)
    @classmethod
    def encrypt_cbc(cls,data,key,iv):
        sub=XSKDF.expand(key,cls.ROUNDS); prev=iv[:8].ljust(8,b"\x00"); out=bytearray()
        for off in range(0,len(data),8):
            blk=data[off:off+8]
            if len(blk)<8: blk=blk+b"\x00"*(8-len(blk))
            c=cls._enc_block(bytes(a^b for a,b in zip(blk,prev)),sub); out+=c; prev=c
        return bytes(out)
    @classmethod
    def decrypt_cbc(cls,data,key,iv):
        sub=XSKDF.expand(key,cls.ROUNDS); prev=iv[:8].ljust(8,b"\x00"); out=bytearray()
        for off in range(0,len(data),8):
            c=data[off:off+8]
            if len(c)<8: c=c+b"\x00"*(8-len(c))
            x=cls._dec_block(c,sub); out+=bytes(a^b for a,b in zip(x,prev)); prev=c
        return bytes(out)

class XSNested:
    @staticmethod
    def _prng(state):
        x=state&MASK64; x^=(x<<13)&MASK64; x^=x>>7; x^=(x<<17)&MASK64; state=x&MASK64
        return state,state&0xFF
    @classmethod
    def _keystream(cls,state,n):
        out=[]
        for _ in range(n): state,b=cls._prng(state); out.append(b)
        return out,state
    @classmethod
    def _apply(cls,data,ops,forward=True):
        buf=list(data); order=range(len(ops)) if forward else range(len(ops)-1,-1,-1)
        for idx in order:
            op,seed=ops[idx]; ks,_=cls._keystream(seed,len(buf))
            if op==0: buf=[b^ks[i] for i,b in enumerate(buf)]
            elif op==1:
                buf=[(b+ks[i])&0xFF for i,b in enumerate(buf)] if forward else [(b-ks[i])&0xFF for i,b in enumerate(buf)]
            elif op==2:
                r=(seed&7) or 1
                if not forward: r=8-r
                buf=[((b<<r)|(b>>(8-r)))&0xFF for b in buf]
            elif op==3: buf=[((b<<4)|(b>>4))&0xFF for b in buf]
            elif op==4:
                nb=bytearray()
                for i in range(0,len(buf),16): nb+=bytes(buf[i:i+16][::-1])
                buf=list(nb)
            else: buf=[b^(((i+1)*31+7)&0xFF) for i,b in enumerate(buf)]
        return bytes(buf)
    @classmethod
    def wrap(cls,data,key,max_layers=24):
        base=struct.unpack("<Q",XSKDF.byte_seed(key)[:8])[0]
        if base==0: base=0xDEADBEEFCAFEBABE
        state=base; ops=[]; n=8+(base%(max_layers-8))
        for _ in range(n):
            state,op=cls._prng(state); op%=6; state,_=cls._prng(state); seed=state^(op<<56); ops.append((op,seed))
        return cls._apply(data,ops,True),ops
    @classmethod
    def unwrap(cls,data,ops): return cls._apply(data,ops,False)
    @staticmethod
    def encode_ops(ops): return b"".join(struct.pack("<BQ",op,seed) for op,seed in ops)
    @staticmethod
    def decode_ops(blob):
        ops=[]
        for off in range(0,len(blob),9): ops.append((blob[off],struct.unpack("<Q",blob[off+1:off+9])[0]))
        return ops

class XSCheck:
    @staticmethod
    def tag(data):
        h=0xCBF29CE484222325
        for b in data: h^=b; h=(h*0x100000001B3)&MASK64
        return len(data),sum(data)&0xFFFF,h
    @classmethod
    def verify(cls,data,clen,csum,fp):
        c,s,h=cls.tag(data); return c==clen and s==csum and h==fp

class XSCipher:
    MAGIC=b"XSN1"
    @classmethod
    def encrypt(cls,data,key):
        clen,csum,fp=XSCheck.tag(data); pad=8-(len(data)%8); padded=data+bytes([pad])*pad
        iv=XSKDF.byte_seed(key+b"\x01iv")[:8]
        c1=XSFeistel.encrypt_cbc(padded,key,iv); c2=XSKeystream.crypt(c1,key+b"\x02stream"); c3,ops=XSNested.wrap(c2,key+b"\x03nest")
        head=cls.MAGIC+iv+struct.pack("<I",clen)+struct.pack("<H",csum)+struct.pack("<Q",fp)
        return head+struct.pack("<H",len(ops))+XSNested.encode_ops(ops)+c3
    @classmethod
    def decrypt(cls,blob,key):
        if blob[:4]!=cls.MAGIC: raise ValueError("not XSCipher")
        p=4; iv=blob[p:p+8]; p+=8
        clen=struct.unpack("<I",blob[p:p+4])[0]; p+=4
        csum=struct.unpack("<H",blob[p:p+2])[0]; p+=2
        fp=struct.unpack("<Q",blob[p:p+8])[0]; p+=8
        nops=struct.unpack("<H",blob[p:p+2])[0]; p+=2
        ops=XSNested.decode_ops(blob[p:p+nops*9]); p+=nops*9
        c2=XSNested.unwrap(blob[p:],ops); c1=XSKeystream.crypt(c2,key+b"\x02stream"); padded=XSFeistel.decrypt_cbc(c1,key,iv)
        pad=padded[-1]
        if not(1<=pad<=8) or padded[-pad:]!=bytes([pad])*pad: raise ValueError("integrity check failed")
        data=padded[:len(padded)-pad]
        if not XSCheck.verify(data,clen,csum,fp): raise ValueError("integrity check failed")
        return data

def _selftest(v=True):
    r=os.urandom
    cases=[b"",b"a",b"hello",r(7),r(8),r(9),b"local x=1\nprint(x)\n"*50,r(1000),r(4096),r(10000),b"\x00"*500,b"A"*333]
    for i,c in enumerate(cases):
        k=r(1+(i%24)); ct=XSCipher.encrypt(c,k); assert XSCipher.decrypt(ct,k)==c
        try: XSCipher.decrypt(ct,b"wrong"); bad=True
        except Exception: bad=False
        assert not bad
        if v: print(f"[ok] {i:2d} {len(c):6d}->{len(ct):6d}")
    ct=bytearray(XSCipher.encrypt(r(500),b"k")); ct[-1]^=0xFF
    try: XSCipher.decrypt(bytes(ct),b"k"); raise AssertionError("no tamper")
    except ValueError: pass
    if v: print("[ok] tamper; ALL PASSED")
    return True
if __name__=="__main__": _selftest()
