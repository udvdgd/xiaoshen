#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hamibot 云脚本解密器"""
def decrypt(data):
    for key in (b"hamibot",b"hamibot123",b"hmbt",b"cloud"):
        out=bytes(b^key[i%len(key)] for i,b in enumerate(data))
        if b"function" in out or b"var " in out: return out
    return data
