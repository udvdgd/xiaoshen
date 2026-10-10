#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
小神算法 · 自研独家算法集 v2
  v1 原语(混淆级): XSKDF / XSKeystream / XSFeistel / XSNested
  XSCipherV2(可靠默认): AES-256-GCM 审计内核 + PBKDF2(400k) + 自研异或外层形态混淆
  说明: 免填密钥自解脚本内部仍含还原材料, 属强混淆; 真正隔离需密钥在外部。仅用于自有/授权内容。
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
        state=(state^word)&MASK32; state=(state*0x45D9F3B+0x9E3779B9)&MASK32
        state^=_rotl32(state,(r*7)&31); state=(state+_rotl32(word|1,(r*13)&31))&MASK32; return state
    @classmethod
    def expand(cls,key,count):
        if not key:key=b"\x00"
        padded=key+b"\x00"*((-len(key))%4); words=list(struct.unpack("<%dI"%(len(padded)//4),padded))
        reg=[0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,0xA4093822,0x299F31D0,0x082EFA98,0xEC4E6C89]
        for i in range(8):reg[i]^=words[i%len(words)]
        sub=[]
        for r in range(count):
            t=cls._mix(reg[r%8],words[r%len(words)],r); t=cls._mix(t,reg[(r+3)%8],r+1); reg[r%8]=t; sub.append(t)
        return sub
    @classmethod
    def byte_seed(cls,key): return b"".join(struct.pack("<I",w) for w in cls.expand(key,64))

class XSKeystream:
    @staticmethod
    def _ks_byte(S,a,b,acc,n):
        a=(a+1)&0xFF; b=(b+S[a]+((acc>>(n&31))&0xFF)+n)&0xFF; S[a],S[b]=S[b],S[a]
        t=S[(S[a]+S[b])&0xFF]
        acc=(_rotl64(acc^(t*0x9E3779B185EBCA87&MASK64),(17+(n&7))&63)+((n+1)*0x100000001B3))&MASK64
        ks=t^(acc&0xFF)^((acc>>23)&0xFF)^((acc>>40)&0xFF); return a,b,acc,ks&0xFF
    @classmethod
    def crypt(cls,data,key):
        seed=XSKDF.byte_seed(key); S=list(range(256)); j=0
        for i in range(256): j=(j+S[i]+seed[i]+((i*31)&0xFF))&0xFF; S[i],S[j]=S[j],S[i]
        for i in range(256): j=(j+S[i]+seed[(i+128)&0xFF]+(seed[i]&0x0F))&0xFF; S[i],S[j]=S[j],S[i]
        a=b=0; acc=(struct.unpack("<Q",seed[:8])[0]^struct.unpack("<Q",seed[8:16])[0])&MASK64
        if acc==0:acc=0x9E3779B97F4A7C15
        out=bytearray(len(data))
        for n,by in enumerate(data): a,b,acc,ks=cls._ks_byte(S,a,b,acc,n); out[n]=by^ks
        return bytes(out)

class XSFeistel:
    ROUNDS=16
    @staticmethod
    def _F(h,sk,r):
        x=(h^sk)&MASK32; x=(x*0x85EBCA6B+0xC2B2AE35)&MASK32; x^=_rotl32(x,(x&15)^(r&15))
        x=(x+_rotl32(sk|1,(r*5)&31))&MASK32; x^=_rotl32(x,11); return x
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
            if len(blk)<8:blk=blk+b"\x00"*(8-len(blk))
            c=cls._enc_block(bytes(a^b for a,b in zip(blk,prev)),sub); out+=c; prev=c
        return bytes(out)
    @classmethod
    def decrypt_cbc(cls,data,key,iv):
        sub=XSKDF.expand(key,cls.ROUNDS); prev=iv[:8].ljust(8,b"\x00"); out=bytearray()
        for off in range(0,len(data),8):
            c=data[off:off+8]
            if len(c)<8:c=c+b"\x00"*(8-len(c))
            x=cls._dec_block(c,sub); out+=bytes(a^b for a,b in zip(x,prev)); prev=c
        return bytes(out)

class XSNested:
    @staticmethod
    def _prng(state):
        x=state&MASK64; x^=(x<<13)&MASK64; x^=x>>7; x^=(x<<17)&MASK64; state=x&MASK64; return state,state&0xFF
    @classmethod
    def _keystream(cls,state,n):
        out=[]
        for _ in range(n):state,b=cls._prng(state);out.append(b)
        return out,state
    @classmethod
    def _apply(cls,data,ops,forward=True):
        buf=list(data); order=range(len(ops)) if forward else range(len(ops)-1,-1,-1)
        for idx in order:
            op,seed=ops[idx]; ks,_=cls._keystream(seed,len(buf))
            if op==0:buf=[b^ks[i] for i,b in enumerate(buf)]
            elif op==1:buf=([(b+ks[i])&0xFF for i,b in enumerate(buf)] if forward else [(b-ks[i])&0xFF for i,b in enumerate(buf)])
            elif op==2:
                r=(seed&7)or 1
                if not forward:r=8-r
                buf=[((b<<r)|(b>>(8-r)))&0xFF for b in buf]
            elif op==3:buf=[((b<<4)|(b>>4))&0xFF for b in buf]
            elif op==4:
                nb=bytearray()
                for i in range(0,len(buf),16):nb+=bytes(buf[i:i+16][::-1])
                buf=list(nb)
            else:buf=[b^(((i+1)*31+7)&0xFF) for i,b in enumerate(buf)]
        return bytes(buf)
    @classmethod
    def wrap(cls,data,key,max_layers=24):
        base=struct.unpack("<Q",XSKDF.byte_seed(key)[:8])[0] or 0xDEADBEEFCAFEBABE; state=base; ops=[]
        for _ in range(8+(base%(max_layers-8))):
            state,op=cls._prng(state);op%=6;state,_=cls._prng(state);ops.append((op,state^(op<<56)))
        return cls._apply(data,ops,True),ops
    @classmethod
    def unwrap(cls,data,ops):return cls._apply(data,ops,False)
    @staticmethod
    def encode_ops(ops):return b"".join(struct.pack("<BQ",op,s) for op,s in ops)
    @staticmethod
    def decode_ops(b):
        return [(b[o],struct.unpack("<Q",b[o+1:o+9])[0]) for o in range(0,len(b),9)]

class XSCheck:
    @staticmethod
    def tag(d):
        h=0xCBF29CE484222325
        for b in d:h^=b;h=(h*0x100000001B3)&MASK64
        return len(d),sum(d)&0xFFFF,h
    @classmethod
    def verify(cls,d,cl,cs,fp):
        a,b,c=cls.tag(d);return a==cl and b==cs and c==fp

class XSCipher:
    MAGIC=b"XSN1"
    @classmethod
    def encrypt(cls,data,key):
        cl,cs,fp=XSCheck.tag(data);pad=8-(len(data)%8);padded=data+bytes([pad])*pad
        iv=XSKDF.byte_seed(key+b"\x01iv")[:8]
        c1=XSFeistel.encrypt_cbc(padded,key,iv);c2=XSKeystream.crypt(c1,key+b"\x02stream");c3,ops=XSNested.wrap(c2,key+b"\x03nest")
        return cls.MAGIC+iv+struct.pack("<I",cl)+struct.pack("<H",cs)+struct.pack("<Q",fp)+struct.pack("<H",len(ops))+XSNested.encode_ops(ops)+c3
    @classmethod
    def decrypt(cls,b,key):
        if b[:4]!=cls.MAGIC:raise ValueError("bad blob")
        p=4;iv=b[p:p+8];p+=8;cl=struct.unpack("<I",b[p:p+4])[0];p+=4;cs=struct.unpack("<H",b[p:p+2])[0];p+=2;fp=struct.unpack("<Q",b[p:p+8])[0];p+=8
        no=struct.unpack("<H",b[p:p+2])[0];p+=2;ops=XSNested.decode_ops(b[p:p+no*9]);p+=no*9
        c1=XSKeystream.crypt(XSNested.unwrap(b[p:],ops),key+b"\x02stream");padded=XSFeistel.decrypt_cbc(c1,key,iv);pad=padded[-1]
        if not(1<=pad<=8)or padded[-pad:]!=bytes([pad])*pad:raise ValueError("integrity failed")
        d=padded[:-pad]
        if not XSCheck.verify(d,cl,cs,fp):raise ValueError("integrity failed")
        return d

class XSCipherV2:
    """可靠默认: AES-256-GCM 审计内核 + PBKDF2(400k) + 自研异或外层形态混淆。无 cryptography 则报错不降级。"""
    MAGIC=b"XSN2";SALT_LEN=16;NONCE_LEN=12;KEY_LEN=32;ITERATIONS=400000
    @staticmethod
    def _available():
        try:import cryptography;return True
        except Exception:return False
    @classmethod
    def encrypt(cls,data,key):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
        except Exception:raise RuntimeError("strong mode needs cryptography")
        salt=os.urandom(16);nonce=os.urandom(12)
        dk=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=cls.ITERATIONS).derive(key or b"\x00")
        inner=salt+nonce+AESGCM(dk).encrypt(nonce,data,None)
        return cls.MAGIC+XSKeystream.crypt(inner,XSKDF.byte_seed(key+b"\x02outer"))
    @classmethod
    def decrypt(cls,b,key):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
        except Exception:raise RuntimeError("needs cryptography")
        if b[:4]!=cls.MAGIC:raise ValueError("bad v2 blob")
        inner=XSKeystream.crypt(b[4:],XSKDF.byte_seed(key+b"\x02outer"))
        salt,nonce=inner[:16],inner[16:28];ct=inner[28:]
        dk=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=cls.ITERATIONS).derive(key or b"\x00")
        try:return AESGCM(dk).decrypt(nonce,ct,None)
        except Exception:raise ValueError("integrity check failed")

XSCipherDefault = XSCipherV2 if XSCipherV2._available() else XSCipher

if __name__=="__main__":
    r=os.urandom
    for c in [b"",b"a",r(9),r(1000),r(50000),b"A"*1000]:
        k=r(12);assert XSCipherDefault.decrypt(XSCipherDefault.encrypt(c,k),k)==c
    print("XSCipher default selftest OK:",XSCipherDefault.__name__)
