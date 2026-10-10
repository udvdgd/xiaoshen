#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELF .so 定向分析器"""
import struct, re
from pathlib import Path
from py.core.utils import extract_strings, looks_like_script
from py.core.decryptors import RC4

class SOAnalyzer:
    ELF_MAGIC=b'\x7fELF'
    ALGO_SIGS={"AES_Sbox":bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5]),"TEA_delta":struct.pack('<I',0x9E3779B9),"TEA_delta_be":struct.pack('>I',0x9E3779B9),"Base64":b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/","Murmur3C1":struct.pack('<I',0xcc9e2d51)}
    FUNC_HINTS=[b"RC4",b"AES",b"xxtea",b"XXTEA",b"decrypt",b"crypt",b"JNI_OnLoad",b"Java_",b"xor",b"base64"]
    def __init__(self,path):
        self.path=Path(path); self.data=self.path.read_bytes()
        self.is_elf=self.data[:4]==self.ELF_MAGIC
        self.key_candidates=[]; self.algo_hits=[]; self.jni_funcs=[]; self.exports=[]
    def analyze(self):
        if not self.is_elf: return None
        self.arch="aarch64" if self.data[4]==2 else "arm32"
        for name,sig in self.ALGO_SIGS.items():
            i=self.data.find(sig)
            if i>=0: self.algo_hits.append((name,i))
        seen=set()
        for off,s in extract_strings(self.data,4,64):
            if s in seen: continue
            seen.add(s); sc=self._score(s)
            self.key_candidates.append((sc,off,s))
            if s.startswith(b"Java_") or s==b"JNI_OnLoad": self.jni_funcs.append((off,s))
            if any(h in s for h in self.FUNC_HINTS) and len(s)<80: self.exports.append((off,s))
        self.key_candidates.sort(key=lambda x:-x[0])
        return {"arch":self.arch,"size":len(self.data),"algo_hits":self.algo_hits,"jni_funcs":self.jni_funcs[:20],"exports":self.exports[:30],"key_candidates":self.key_candidates[:30]}
    def _score(self,s):
        if not 4<=len(s)<=64: return 0
        sc=4 if len(s) in (5,6,8,16,24,32) else 0
        for kw in (b"key",b"Key",b"secret",b"aes",b"rc4",b"iv",b"password",b"token",b"xxtea",b"lua",b"cocos",b"script",b"encrypt"):
            if kw in s: sc+=3
        if re.fullmatch(rb'[0-9a-fA-F]{16,64}',s): sc+=3
        if s in {b"2dxLua",b"XXTEA",b"autojs",b"hyb1996",b"touchsprite",b"hamibot"}: sc+=10
        for bad in (b"libc.so","libart","/system/","/data/","http","__","Android"):
            if bad in s: sc-=10
        return sc
    def try_decrypt(self,cipher):
        results=[]
        for sc,off,k in self.key_candidates[:20]:
            for name,fn in [("RC4",RC4.crypt),("XOR",lambda d,kk:bytes(b^kk[i%len(kk)] for i,b in enumerate(d)))]:
                try:
                    out=fn(cipher,k)
                    if looks_like_script(out): results.append((name,k,out))
                except: pass
        return results
