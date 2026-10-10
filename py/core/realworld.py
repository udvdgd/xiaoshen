#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实战加密方案: AutoJs6 AES / Cocos2d XXTEA / TouchSprite / Gopy"""
import struct, hashlib
from py.core.decryptors import XXTEA, AES, RC4

class AutoJs6:
    HEADER=b"EncryptedScriptFileHeader"
    @staticmethod
    def decrypt(data):
        if data[:25]!=AutoJs6.HEADER: return {"success":False}
        body=data[25:]
        for pkg,ver in [("org.autojs.autojs6","6.7.0"),("com.example.myapp","1.0.0")]:
            key=hashlib.md5((pkg+ver+"main.js").encode()).digest()
            try:
                out=AES.decrypt_ecb(body,key)
                if any(k in out[:300] for k in (b"function",b"var ",b"//",b"const")):
                    return {"success":True,"data":out,"method":f"AutoJs6 {pkg}"}
            except: pass
        return {"success":False}

class Cocos2d:
    @staticmethod
    def xxtea_decrypt(data):
        if data[:5]!=b"XXTEA": return data
        return XXTEA.decrypt(data[5:],b"2dxLua".ljust(16,b'\x00')[:16])
    @staticmethod
    def abcd_xor(data):
        if len(data)<12 or data[:4]!=b"abcd": return data
        k=struct.pack(">I",struct.unpack(">I",data[4:8])[0]-2048)
        body=data[8:-8] if len(data)>16 else data[8:]
        return bytes(b^k[i%4] for i,b in enumerate(body))

class TouchSprite:
    @staticmethod
    def xor_3c(data):
        out=bytes([data[0]]+[b^0x3C for b in data[1:]])
        return out if out[:4]==b'\x1bLua' else data

class Gopy:
    KEY=b"jzxc36g3PqBhmV44kI8"
    @staticmethod
    def decrypt(data): return RC4.crypt(data,Gopy.KEY)

def auto_detect_real(data):
    if data[:25]==AutoJs6.HEADER:
        r=AutoJs6.decrypt(data)
        if r.get("success"): return r
    if data[:5]==b"XXTEA": return {"method":"Cocos2d","data":Cocos2d.xxtea_decrypt(data),"success":True}
    if data[:4]==b"abcd": return {"method":"abcd","data":Cocos2d.abcd_xor(data),"success":True}
    if len(data)>4 and bytes([data[0]]+[b^0x3C for b in data[1:5]])[:4]==b'\x1bLua':
        return {"method":"TouchSprite","data":TouchSprite.xor_3c(data),"success":True}
    return {"method":"unknown","data":data,"success":False}
