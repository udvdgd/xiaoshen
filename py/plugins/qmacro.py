#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按键精灵系列解密器"""
def decrypt(data):
    xor_table=[0x0A,0x1B,0x3C,0x5D,0x7E,0x9F,0xA0,0xC1]
    out=bytes(b^xor_table[i%8] for i,b in enumerate(data))
    if b"Sub" in out or b"KeyPress" in out or b"Rem" in out: return out
    key=b"mqmacro"
    out2=bytes(b^key[i%len(key)] for i,b in enumerate(data))
    if b"Sub" in out2 or b"KeyPress" in out2: return out2
    return data
