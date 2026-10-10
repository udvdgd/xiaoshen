#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AutoJS 系列解密器"""
import re, base64
from py.core.decryptors import Decryptors

def decrypt(data):
    for key in (b"autojs",b"auto.js",b"hyb1996",b"\x55"*8):
        out=bytes(b^key[i%len(key)] for i,b in enumerate(data))
        if b"function" in out or b"var " in out or b"//" in out: return out
    try:
        txt=data.decode('utf-8',errors='ignore')
        m=re.search(r"(?:atob|fromBase64|Base64\.decode)\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]",txt)
        if m: return base64.b64decode(m.group(1))
    except: pass
    return data
