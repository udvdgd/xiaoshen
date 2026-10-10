#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lua 反混淆辅助"""
import re

def decrypt(data):
    if data[:4]==b'\x1bLua':
        return (f"-- [小神] Lua 字节码 版本={data[4]:#x}, 用 unluac 还原\n").encode()+data
    strs=re.findall(rb'[\x20-\x7e]{6,}',data[:4096])
    if strs:
        out="-- [小神] Lua 常量提取:\n".encode()
        for s in strs[:30]: out+=b"-- "+s+b"\n"
        return out+data
    return data
