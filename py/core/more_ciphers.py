#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""壳变形算法库: RC4-drop / RollingXOR / CustomBase64 / RotateXOR / LuaByteUnpack"""
import base64

def rc4_raw(data,key):
    S=list(range(256)); j=0
    for i in range(256): j=(j+S[i]+key[i%len(key)])%256; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for byte in data:
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        out.append(byte^S[(S[i]+S[j])%256])
    return bytes(out)

def rc4_drop(data,key,drop=256):
    S=list(range(256)); j=0
    for i in range(256): j=(j+S[i]+key[i%len(key)])%256; S[i],S[j]=S[j],S[i]
    i=j=0
    for _ in range(drop):
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
    out=bytearray()
    for byte in data:
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        out.append(byte^S[(S[i]+S[j])%256])
    return bytes(out)

def rolling_xor(data,key):
    return bytes(b^key[i%len(key)]^(i&0xFF) for i,b in enumerate(data))

_STD="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
def custom_b64decode(s,alphabet):
    table={c:i for i,c in enumerate(alphabet)}; s=s.rstrip("="); bits=0; acc=0; out=bytearray()
    for ch in s:
        if ch not in table: continue
        acc=(acc<<6)|table[ch]; bits+=6
        if bits>=8:
            bits-=8; out.append((acc>>bits)&0xFF); acc&=(1<<bits)-1
    return bytes(out)

def rot_xor(data,key,r=3,invert=False):
    out=bytearray()
    for i,b in enumerate(data):
        if invert:
            v=((b>>r)|(b<<(8-r)))&0xFF; out.append(v^key[i%len(key)])
        else:
            v=b^key[i%len(key)]; out.append(((v<<r)|(v>>(8-r)))&0xFF)
    return bytes(out)

def lua_byte_unpack(data,key0):
    return bytes(b^((key0+i)&0xFF) for i,b in enumerate(data))

def try_variant_decrypt(data):
    head=data[:512]; KW=(b"function",b"local ",b"print(",b"gg.",b"http",b"--",b"return")
    def good(p):
        bad=sum(1 for x in p if x<9 or (13<x<32) or x==127)
        if bad/max(1,len(p))>0.05: return False
        return any(k in p for k in KW)
    for k0 in range(256):
        p=lua_byte_unpack(head,k0)
        if good(p): return lua_byte_unpack(data,k0),f"lua_byte_unpack({k0})"
    for klen in (1,2,4):
        for kv in range(256):
            key=bytes([kv])*klen; p=rolling_xor(head,key)
            if good(p): return rolling_xor(data,key),f"rolling_xor"
    return None

if __name__=="__main__":
    assert rc4_raw(rc4_raw(b"hi",b"k"),b"k")==b"hi"
    assert rolling_xor(rolling_xor(b"abc",b"\x01"),b"\x01")==b"abc"
    print("more_ciphers ok")
