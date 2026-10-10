#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

def _score(b):
    if not b: return -1.0
    bad=sum(1 for x in b if x<9 or (13<x<32) or x==127)
    if bad: return -1.0
    s=sum(1 for x in b if 32<=x<=126)/len(b)
    try: b.decode("utf-8"); s+=0.5
    except UnicodeDecodeError: pass
    return s

_HEX_DQ=re.compile(rb'"((?:\\x[0-9a-fA-F]{2})+)"')

def _rc4_crypt(data,key):
    S=list(range(256)); j=0; klen=len(key)
    for i in range(256):
        j=(j+S[i]+key[i%klen])%256; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for byte in data:
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        out.append(byte^S[(S[i]+S[j])%256])
    return bytes(out)

def _unhex(esc):
    return bytes(int(p,16) for p in re.findall(rb"\\x([0-9a-fA-F]{2})",esc))

def decrypt_blob(cipher):
    best=(b"",-1,-1.0)
    for k in range(1,301):
        try: pt=_rc4_crypt(cipher,str(k).encode())
        except Exception: continue
        sc=_score(pt)
        if sc>best[2]: best=(pt,k,sc)
    return best[0],best[1]

def decrypt(data):
    blobs=_HEX_DQ.findall(data); recovered=0; out=data
    for (s,e) in reversed([m.span() for m in _HEX_DQ.finditer(data)]):
        cipher=_unhex(data[s+1:e-1]); pt,k=decrypt_blob(cipher)
        if _score(pt)>=0.3:
            lit=b'"'+pt.replace(b"\\",b"\\\\").replace(b'"',b'\\"')+b'"'
            out=out[:s]+lit+out[e:]; recovered+=1
    return {"type":"不羡仙gg-Lua","success":recovered>0,"output":out,"recovered":recovered,"total_blobs":len(blobs)}

def is_buxianxian(data):
    if b"RC4RRR" in data or b"gg.internal2" in data[:2000]: return True
    return len(_HEX_DQ.findall(data))>=3

def decrypt_bytes(data): return decrypt(data)["output"]
