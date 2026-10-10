#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
小神算法 v4.1 · 企业级解密算法库
  编码/压缩/对称(AES,RC4,TEA,XTEA,XXTEA,ChaCha20,SM4,Blowfish)/哈希/KDF/异或/爆破
  仅用于自有/获授权文件、CTF 与教学等正当场景。
"""
import re, struct, base64, zlib, gzip, hashlib, hmac, itertools, subprocess, shutil

def _rotl32(v,n): return ((v<<n)|(v>>(32-n)))&0xFFFFFFFF

def looks_like_script(data):
    if len(data)<4: return False
    head=data[:500]
    kws=[b"function",b"var ",b"let ",b"const ",b"import ",b"local ",b"//",b"/*",b"#include",b"require(",b"console.",b"print(",b"return ",b"if ",b"for ",b"device.",b"toast(",b"auto.",b"<html",b"#!/",b"module.",b"exports.",b"process.",b"window."]
    return sum(head.count(k) for k in kws)>=1

def entropy(data):
    if not data: return 0.0
    from collections import Counter
    import math
    c=Counter(data); n=len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

class Encoding:
    @staticmethod
    def b64(data):
        try: return base64.b64decode(data,validate=True)
        except Exception: return data
    @staticmethod
    def b64url(data):
        try: return base64.urlsafe_b64decode(data+b"="*(-len(data)%4))
        except Exception: return data
    @staticmethod
    def b32(data):
        try: return base64.b32decode(data)
        except Exception: return data
    @staticmethod
    def b16(data):
        try: return base64.b16decode(data)
        except Exception: return data
    @staticmethod
    def hex(data):
        try:
            t=data.decode().strip()
            if re.fullmatch(r"[0-9a-fA-F\s]+",t): return bytes.fromhex(t.replace(" ",""))
        except Exception: pass
        return data
    @staticmethod
    def rot13(data):
        out=bytearray()
        for b in data:
            if 0x41<=b<=0x5A: out.append(((b-0x41+13)%26)+0x41)
            elif 0x61<=b<=0x7A: out.append(((b-0x61+13)%26)+0x61)
            else: out.append(b)
        return bytes(out)
    @staticmethod
    def reverse(data): return data[::-1]
    @staticmethod
    def url_decode(data):
        try:
            from urllib.parse import unquote
            return unquote(data.decode("utf-8","ignore")).encode()
        except Exception: return data

class Compression:
    @staticmethod
    def zlib(data):
        try: return zlib.decompress(data)
        except Exception:
            try: return zlib.decompress(data,-15)
            except Exception: return data
    @staticmethod
    def gzip(data):
        try: return gzip.decompress(data)
        except Exception: return data
    @staticmethod
    def bz2(data):
        try:
            import bz2; return bz2.decompress(data)
        except Exception: return data
    @staticmethod
    def lzma(data):
        try:
            import lzma; return lzma.decompress(data)
        except Exception: return data

class RC4:
    @staticmethod
    def crypt(data,key):
        S=list(range(256)); j=0; klen=len(key)
        for i in range(256):
            j=(j+S[i]+key[i%klen])&0xFF; S[i],S[j]=S[j],S[i]
        i=j=0; out=bytearray()
        for b in data:
            i=(i+1)&0xFF; j=(j+S[i])&0xFF; S[i],S[j]=S[j],S[i]
            out.append(b^S[(S[i]+S[j])&0xFF])
        return bytes(out)
    @staticmethod
    def crypt_drop(data,key,drop=768):
        S=list(range(256)); j=0; klen=len(key)
        for i in range(256):
            j=(j+S[i]+key[i%klen])&0xFF; S[i],S[j]=S[j],S[i]
        i=j=0; out=bytearray(); n=0
        for b in data:
            i=(i+1)&0xFF; j=(j+S[i])&0xFF; S[i],S[j]=S[j],S[i]
            k=S[(S[i]+S[j])&0xFF]
            if n<drop: n+=1; continue
            out.append(b^k)
        return bytes(out)

class TEA:
    @staticmethod
    def decrypt(v,key,rounds=32):
        v0,v1=v[0],v[1]; k0,k1,k2,k3=key; delta=0x9E3779B9; s=(delta*rounds)&0xFFFFFFFF
        for _ in range(rounds):
            v1=(v1-(((v0<<4)+k2)^(v0+s)^((v0>>5)+k3)))&0xFFFFFFFF
            v0=(v0-(((v1<<4)+k0)^(v1+s)^((v1>>5)+k1)))&0xFFFFFFFF
            s=(s-delta)&0xFFFFFFFF
        return [v0,v1]

class XTEA:
    @staticmethod
    def decrypt(v,key,rounds=32):
        v0,v1=v[0],v[1]; delta=0x9E3779B9; s=(delta*rounds)&0xFFFFFFFF
        for _ in range(rounds):
            v1=(v1-((((v0<<4)^(v0>>5))+v0)^(s+key[(s>>11)&3]))&0xFFFFFFFF
            v0=(v0-((((v1<<4)^(v1>>5))+v1)^(s+key[s&3])))&0xFFFFFFFF
            s=(s-delta)&0xFFFFFFFF
        return [v0,v1]

class XXTEA:
    @staticmethod
    def decrypt(data,key):
        n=len(data)//4
        if n<2: return data
        v=list(struct.unpack("<%dI"%n,data[:n*4]))
        k=list(struct.unpack("<4I",key.ljust(16,b"\x00")[:16]))
        delta=0x9E3779B9; rounds=6+52//n; s=(rounds*delta)&0xFFFFFFFF; y=v[0]
        while s!=0:
            e=(s>>2)&3
            for p in range(n-1,0,-1):
                z=v[p-1]
                mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((s^y)+(k[(p&3)^e]^z)))
                v[p]=(v[p]-mx)&0xFFFFFFFF; y=v[p]
            z=v[n-1]
            mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((s^y)+(k[e]^z)))
            v[0]=(v[0]-mx)&0xFFFFFFFF; y=v[0]; s=(s-delta)&0xFFFFFFFF
        return struct.pack("<%dI"%n,*v)

class AES:
    SBOX=[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
    INV_SBOX=[0]*256
    for _i,_v in enumerate(SBOX): INV_SBOX[_v]=_i
    @staticmethod
    def _xtime(a): return ((a<<1)^0x1B)&0xFF if a&0x80 else (a<<1)
    @staticmethod
    def _gf_mul(a,b):
        r=0
        for _ in range(8):
            if b&1: r^=a
            hi=a&0x80; a=(a<<1)&0xFF
            if hi: a^=0x1B
            b>>=1
        return r
    @classmethod
    def _expand_key(cls,key):
        w=[list(key[4*i:4*i+4]) for i in range(4)]; rcon=1
        for i in range(4,44):
            t=list(w[i-1])
            if i%4==0:
                t=t[1:]+t[:1]; t=[cls.SBOX[b] for b in t]; t[0]^=rcon; rcon=cls._xtime(rcon)
            w.append([w[i-4][j]^t[j] for j in range(4)])
        return w
    @classmethod
    def _inv_block(cls,block,w):
        block=list(block)
        for i in range(16): block[i]^=w[i//4][i%4]
        for rnd in range(9,0,-1):
            s=list(block)
            for row in range(1,4):
                rv=[s[row+4*c] for c in range(4)]; rv=rv[-row:]+rv[:-row]
                for c in range(4): s[row+4*c]=rv[c]
            block=[cls.INV_SBOX[b] for b in s]
            rk=w[4*rnd:4*rnd+4]
            for i in range(16): block[i]^=rk[i//4][i%4]
            ob=list(block)
            for c in range(4):
                col=[block[4*c],block[4*c+1],block[4*c+2],block[4*c+3]]
                ob[4*c]=(cls._gf_mul(col[0],14)^cls._gf_mul(col[1],11)^cls._gf_mul(col[2],13)^cls._gf_mul(col[3],9))
                ob[4*c+1]=(cls._gf_mul(col[0],9)^cls._gf_mul(col[1],14)^cls._gf_mul(col[2],11)^cls._gf_mul(col[3],13))
                ob[4*c+2]=(cls._gf_mul(col[0],13)^cls._gf_mul(col[1],9)^cls._gf_mul(col[2],14)^cls._gf_mul(col[3],11))
                ob[4*c+3]=(cls._gf_mul(col[0],11)^cls._gf_mul(col[1],13)^cls._gf_mul(col[2],9)^cls._gf_mul(col[3],14))
            block=ob
        s=list(block)
        for row in range(1,4):
            rv=[s[row+4*c] for c in range(4)]; rv=rv[-row:]+rv[:-row]
            for c in range(4): s[row+4*c]=rv[c]
        block=[cls.INV_SBOX[b] for b in s]; rk=w[0:4]
        for i in range(16): block[i]^=rk[i//4][i%4]
        return bytes(block)
    @classmethod
    def decrypt_ecb(cls,data,key):
        key=key.ljust(16,b"\x00")[:16]
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
            d=Cipher(algorithms.AES(key),modes.ECB()).decryptor(); return d.update(data)+d.finalize()
        except Exception:
            w=cls._expand_key(key); out=bytearray()
            for off in range(0,len(data)-15,16): out.extend(cls._inv_block(data[off:off+16],w))
            return bytes(out)
    @classmethod
    def decrypt_cbc(cls,data,key,iv):
        key=key.ljust(16,b"\x00")[:16]
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
            d=Cipher(algorithms.AES(key),modes.CBC(iv)).decryptor(); return d.update(data)+d.finalize()
        except Exception:
            w=cls._expand_key(key); out=bytearray(); prev=iv
            for off in range(0,len(data)-15,16):
                blk=data[off:off+16]; out.extend(bytes(a^b for a,b in zip(cls._inv_block(blk,w),prev))); prev=blk
            return bytes(out)

class ChaCha20:
    CONST=b"expand 32-byte k"
    @staticmethod
    def _qr(w,a,b,c,d):
        w[a]=(w[a]+w[b])&0xFFFFFFFF; w[d]^=w[a]; w[d]=_rotl32(w[d],16)
        w[c]=(w[c]+w[d])&0xFFFFFFFF; w[b]^=w[c]; w[b]=_rotl32(w[b],12)
        w[a]=(w[a]+w[b])&0xFFFFFFFF; w[d]^=w[a]; w[d]=_rotl32(w[d],8)
        w[c]=(w[c]+w[d])&0xFFFFFFFF; w[b]^=w[c]; w[b]=_rotl32(w[b],7)
    @staticmethod
    def decrypt(key,nonce,data,counter=0):
        key=key.ljust(32,b"\x00")[:32]; nonce=nonce.ljust(12,b"\x00")[:12]
        c=struct.unpack("<4I",ChaCha20.CONST); k=struct.unpack("<8I",key); n=struct.unpack("<3I",nonce)
        out=bytearray(); pos=0
        while pos<len(data):
            s=list(c)+list(k)+[counter&0xFFFFFFFF]+list(n); w=list(s)
            for _ in range(10):
                for q in ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)): ChaCha20._qr(w,*q)
            for i in range(16): w[i]=(w[i]+s[i])&0xFFFFFFFF
            ks=struct.pack("<16I",*w); ch=data[pos:pos+64]
            out.extend(ch[i]^ks[i] for i in range(len(ch))); pos+=64; counter+=1
        return bytes(out)

class SM4:
    SBOX=[0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x59,0x0f,0xdb,0xe0,0x00,0x82,0xeb,0x27,0xb2,0x75,0x0a,0x94,0x5b,0x1b,0x9d,0x5e,0x20,0x50,0xb0,0x3a,0x4a,0xbc,0xc4,0x5c,0xc6,0x6b,0x4d,0x92,0x7f,0x63,0x60,0x73,0xe7,0x0f,0x9e,0x25,0x1a,0x7b,0x68,0x83,0xee,0xb8,0x49,0x2d,0x8e,0x47,0x4e,0x1b,0x38,0x89,0xcb,0x30,0x89,0x15,0x3b,0xd9,0x32,0x1b,0x4c,0x7e,0x07,0x9f,0xc0,0x7c,0x2f,0x1a,0x5f,0x85,0x93,0x21,0x1a,0x6f,0x9d,0x74,0xbe,0xc8,0x5f,0x1a,0x35,0xaf,0x2a,0x64,0x48,0x30,0x15,0x7e,0x07,0xb1,0x2f,0xad,0x5a,0x3b,0x9e,0x3c,0x5f,0xd0,0x20,0xec,0x1b,0x3f,0x8d,0x34,0x7c,0x0f,0x8b,0xc8,0x1d,0x3a,0x2b,0x5f,0x00,0x30,0x95,0xbf,0x1a,0xe5,0x2f,0x4b,0x3e,0x46,0x7f,0x90,0x1e,0x2b,0x7a,0x03,0x56,0x1e,0x48,0x30,0x33,0x17,0x4a,0x5b,0x85,0x33,0x1c,0x81,0x7a,0x2e,0x10,0x46,0x8b,0x20,0x6a,0x48,0x96,0x38,0x8c,0x1a,0x4e,0x1b,0x3d,0x97,0x3f,0x0a,0x7e,0x4e,0x3c,0x2b,0x4a,0x6f,0xd2,0x2e,0x20,0x30,0x96,0x4a,0x4f,0x1e,0x6c,0x50,0x0d,0x3e,0x72,0x0a,0x1e,0x2e,0x4a,0x7a,0x6f,0x2e,0x80,0x7b,0x2a,0x5f,0x0c,0x3a,0x2b,0xe9,0x4a,0x1e,0x3b,0x6f,0x0f,0x48,0x5e,0x30]
    FK=[0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC]
    CK=[0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279]
    @staticmethod
    def _tau(a): return bytes(SM4.SBOX[b] for b in a)
    @staticmethod
    def _T(x):
        b=struct.unpack("<I",SM4._tau(struct.pack("<I",x)))[0]
        return b^_rotl32(b,2)^_rotl32(b,10)^_rotl32(b,18)^_rotl32(b,24)
    @staticmethod
    def _Tp(x):
        b=struct.unpack("<I",SM4._tau(struct.pack("<I",x)))[0]
        return b^_rotl32(b,13)^_rotl32(b,23)
    @staticmethod
    def _ks(key):
        mk=struct.unpack("<4I",key[:16]); k=[mk[i]^SM4.FK[i] for i in range(4)]; rk=[]
        for i in range(32):
            f=k[0]^SM4._Tp(k[1]^k[2]^k[3]^SM4.CK[i]); rk.append(f); k=[k[1],k[2],k[3],f]
        return rk
    @staticmethod
    def decrypt(data,key):
        key=key.ljust(16,b"\x00")[:16]; rk=SM4._ks(key); out=bytearray()
        for off in range(0,len(data)-15,16):
            x=list(struct.unpack("<4I",data[off:off+16]))
            for i in range(32):
                f=x[0]^SM4._T(x[1]^x[2]^x[3]^rk[i]); x=[x[1],x[2],x[3],f]
            out.extend(struct.pack("<4I",x[3],x[2],x[1],x[0]))
        return bytes(out)

class Blowfish:
    @staticmethod
    def decrypt(data,key):
        if not shutil.which("openssl"): return data
        try:
            p=subprocess.run(["openssl","enc","-d","-bf-ecb","-K",key.hex(),"-nopad"],input=data,capture_output=True)
            return p.stdout if p.stdout else data
        except Exception: return data

class XOREngine:
    @staticmethod
    def single_byte(data,key): return bytes(b^key for b in data)
    @staticmethod
    def multi_byte(data,key):
        klen=len(key); return bytes(b^key[i%klen] for i,b in enumerate(data))
    @staticmethod
    def vigenere(data,key):
        out=bytearray(); ki=0
        for b in data: out.append(b^key[ki%len(key)]); ki+=1
        return bytes(out)
    @staticmethod
    def reverse_then_xor(data,key): return XOREngine.multi_byte(data[::-1],key)[::-1]
    @staticmethod
    def xor_brute_single(data):
        kws=[(b"function",8),(b"local ",6),(b"import ",6),(b"require",6),(b"return",5),(b"const ",4),(b"var ",3),(b"//",2),(b"#include",6),(b"def ",4)]
        sample=data[:800]; n=len(sample); best,bs=data,0
        for k in range(1,256):
            out=bytes(b^k for b in sample); s=sum(out.count(kw)*w for kw,w in kws)
            if s==0: continue
            pr=sum(1 for b in out if 9<=b<=13 or 32<=b<=126); s+=int(pr*6/max(n,1))
            s-=sum(1 for b in out if not(9<=b<=13 or 32<=b<=126))
            if s>bs: best,bs=bytes(b^k for b in data),s
        return best if bs>0 else data

class Hash:
    @staticmethod
    def md5(d): return hashlib.md5(d).hexdigest()
    @staticmethod
    def sha1(d): return hashlib.sha1(d).hexdigest()
    @staticmethod
    def sha256(d): return hashlib.sha256(d).hexdigest()
    @staticmethod
    def sha512(d): return hashlib.sha512(d).hexdigest()
    @staticmethod
    def blake2b(d):
        try: return hashlib.blake2b(d).hexdigest()
        except Exception: return ""

class KDF:
    @staticmethod
    def pbkdf2(password,salt,iters,dklen,hname="sha256"):
        hlen=hashlib.new(hname).digest_size; out=b""
        for i in range(1,(dklen+hlen-1)//hlen+1):
            U=hmac.new(password,salt+struct.pack(">I",i),getattr(hashlib,hname)).digest(); T=U
            for _ in range(1,iters): U=hmac.new(password,U,getattr(hashlib,hname)).digest(); T=bytes(a^b for a,b in zip(T,U))
            out+=T
        return out[:dklen]
    @staticmethod
    def simple_hash_key(password,salt,length=16): return hashlib.sha256(password+salt).digest()[:length]

class BruteEngine:
    COMMON_WORDS=[b"123456",b"password",b"admin",b"autojs",b"script",b"touchsprite",b"hamibot",b"qmacro",b"key",b"test",b"root",b"abc123",b"game",b"cheat",b"hack",b"android",b"xiaoshen",b"auto",b"pro",b"vip",b"12345678",b"abcdef"]
    CHARSETS=["0123456789","abcdefghijklmnopqrstuvwxyz","0123456789abcdef","abcdefghijklmnopqrstuvwxyz0123456789","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    @staticmethod
    def score(data):
        if len(data)<4: return 0
        head=data[:500]
        kws=[b"function",b"var ",b"import",b"local",b"require",b"console.",b"print(",b"return",b"//",b"#",b"toast(",b"device.",b"if ",b"for ",b"while",b"auto."]
        s=sum(head.count(k)*10 for k in kws); pr=sum(1 for b in head if 0x20<=b<=0x7e or b in (9,10,13)); s+=(pr*5)//max(1,len(head)); return s
    @staticmethod
    def crack(data,algo="rc4",max_len=4):
        bs,bk,bo,tried=0,None,None,0
        def test(key):
            out=RC4.crypt(data,key) if algo=="rc4" else XOREngine.multi_byte(data,key); return BruteEngine.score(out),out
        for w in BruteEngine.COMMON_WORDS:
            tried+=1; s,out=test(w)
            if s>bs: bs,bk,bo=s,w,out
            if s>=80: return bo,bk,tried
        for cs in BruteEngine.CHARSETS:
            for length in range(1,max_len+1):
                if bs>=80: break
                for combo in itertools.product(cs,repeat=length):
                    key="".join(combo).encode(); tried+=1; s,out=test(key)
                    if s>bs: bs,bk,bo=s,key,out
                    if s>=80: return bo,bk,tried
        return bo,bk,tried

class PlatformDecryptors:
    @staticmethod
    def autojs(data):
        for key in (b"autojs",b"auto.js",b"hyb1996"):
            out=XOREngine.multi_byte(data,key)
            if b"function" in out or b"var " in out: return out
        return data
    @staticmethod
    def qmacro(data):
        t=[0x0A,0x1B,0x3C,0x5D,0x7E,0x9F,0xA0,0xC1]; out=bytes(b^t[i%8] for i,b in enumerate(data))
        return out if b"Sub" in out or b"KeyPress" in out else data
    @staticmethod
    def touchsprite(data):
        for key in (b"touchsprite",b"TouchSprite",b"tsprite"):
            out=XOREngine.multi_byte(data,key)
            if b"function" in out or b"local" in out: return out
        return data
    @staticmethod
    def hamibot(data):
        for key in (b"hamibot",b"hamibot123",b"hmbt"):
            out=XOREngine.multi_byte(data,key)
            if b"function" in out or b"var " in out: return out
        return data

class Deobfuscator:
    @staticmethod
    def js_obfuscator(data):
        txt=data.decode("utf-8","ignore"); m=re.search(r"(?:var|let|const)\s+(_0x\w+)\s*=\s*\[(.*?)\];",txt,re.S)
        if not m: return data
        strs=re.findall(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"",m.group(2))
        out="// [小神] 字符串数组:\n"
        for i,s in enumerate(x[0] or x[1] for x in strs): out+=f"// [{i}] {s}\n"
        return (out+"\n"+txt).encode("utf-8","ignore")
    @staticmethod
    def lua_constants(data):
        if data[:4]==b"\x1bLua": return (f"-- Lua bytecode v{data[4]:#x}\n".encode()+data)
        strs=re.findall(rb"[\x20-\x7e]{6,}",data[:4096])
        if strs:
            out=b"-- constants:\n"
            for s in strs[:30]: out+=b"-- "+s+b"\n"
            return out+data
        return data

_COMMON_RC4_KEYS=[b"autojs",b"auto.js",b"hyb1996",b"AutoJs6",b"touchsprite",b"TouchSprite",b"tsprite",b"hamibot",b"HamiBot",b"2dxLua",b"cocos2d",b"cocos",b"jzxc36g3PqBhmV44kI8",b"key",b"123456",b"password",b"admin",b"secret"]
_SCRIPT_MARKS=[b"function",b"local ",b"var ",b"import ",b"require",b"return",b"//",b"#include",b"def ",b"const "]

def _script_score(data):
    head=data[:1500]; sc=sum(head.count(m)*5 for m in _SCRIPT_MARKS)
    sc+=sum(1 for b in head[:400] if 9<=b<=13 or 32<=b<=126); sc-=sum(1 for b in head[:200] if b==0)*3; return sc

class Decryptors:
    b64=staticmethod(Encoding.b64); b64url=staticmethod(Encoding.b64url); b32=staticmethod(Encoding.b32); hex_dec=staticmethod(Encoding.hex)
    zlib_dec=staticmethod(Compression.zlib); gzip_dec=staticmethod(Compression.gzip); bz2_dec=staticmethod(Compression.bz2); lzma_dec=staticmethod(Compression.lzma)
    rc4=staticmethod(RC4.crypt); rc4_drop=staticmethod(RC4.crypt_drop); xxtea_decrypt=staticmethod(XXTEA.decrypt)
    xor_single_byte=staticmethod(XOREngine.xor_brute_single); xor_multi_byte=staticmethod(XOREngine.multi_byte)
    @staticmethod
    def try_rc4_common(data):
        base=_script_score(data); best,bs=data,base
        for key in _COMMON_RC4_KEYS:
            try:
                out=RC4.crypt(data,key); s=_script_score(out)
                if s>bs: best,bs=out,s
            except Exception: continue
        return best if bs>base else data
