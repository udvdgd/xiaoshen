#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小神算法 - 通用工具"""

import os
import sys
import re
import base64
from pathlib import Path

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
    B = '\033[94m'; P = '\033[95m'; C = '\033[96m'
    W = '\033[97m'; N = '\033[0m'; BOLD = '\033[1m'

def disable_color():
    for k in ['R','G','Y','B','P','C','W','N','BOLD']:
        setattr(C, k, '')

def looks_like_script(data: bytes) -> bool:
    if len(data) < 4:
        return False
    head = data[:500]
    keywords = [b"function", b"var ", b"let ", b"const ", b"import ",
                b"local ", b"//", b"/*", b"#include", b"require(",
                b"console.", b"print(", b"return ", b"if ", b"for ",
                b"device.", b"toast(", b"<html", b"#!/"]
    return sum(head.count(kw) for kw in keywords) >= 1

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    import math
    cnt = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in cnt.values())

def extract_strings(data: bytes, min_len=4, max_len=128):
    out = []
    for m in re.finditer(rb'[\x20-\x7e]{%d,%d}' % (min_len, max_len), data):
        out.append((m.start(), m.group()))
    return out

def is_elf(data: bytes) -> bool:
    return data[:4] == b'\x7fELF'

def is_zip(data: bytes) -> bool:
    return data[:2] == b'PK'

def is_gzip(data: bytes) -> bool:
    return data[:2] == b'\x1f\x8b'

def safe_decode(data: bytes) -> str:
    try:
        return data.decode('utf-8')
    except:
        try:
            return data.decode('gbk')
        except:
            return data.decode('latin-1', errors='replace')
