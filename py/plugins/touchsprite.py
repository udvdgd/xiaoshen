#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""触动精灵系列解密器"""
import struct
from py.core.decryptors import Decryptors

def decrypt(data):
    if data[:4]==b'\x1bLua': return data
    for key in (b"touchsprite",b"TouchSprite",b"tsprite",b"ts123456"):
        out=bytes(b^key[i%len(key)] for i,b in enumerate(data))
        if b"function" in out or b"local" in out or b"require" in out: return out
    for key in (b"touchsprite\x00"*2,):
        try:
            out=Decryptors.xxtea_decrypt(data,key)
            if b"function" in out or b"local" in out: return out
        except: pass
    return data
