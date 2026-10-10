#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, re, base64

class C:
    R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'
    P='\033[95m'; C='\033[96m'; W='\033[97m'; N='\033[0m'; BOLD='\033[1m'

def disable_color():
    for k in ['R','G','Y','B','P','C','W','N','BOLD']: setattr(C,k,'')

def looks_like_script(data):
    if len(data)<4: return False
    head=data[:500]
    kws=[b"function",b"var ",b"let ",b"const ",b"import ",b"local ",b"//",b"/*",b"#include",b"require(",b"console.",b"print(",b"return ",b"if ",b"for ",b"device.",b"toast(",b"<html",b"#!/"]
    return sum(head.count(k) for k in kws)>=1

def entropy(data):
    if not data: return 0.0
    from collections import Counter; import math
    cnt=Counter(data); n=len(data)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values())

def extract_strings(data,min_len=4,max_len=128):
    return [(m.start(),m.group()) for m in re.finditer(rb'[\x20-\x7e]{%d,%d}'%(min_len,max_len),data)]

def is_elf(data): return data[:4]==b'\x7fELF'
def is_zip(data): return data[:2]==b'PK'
def is_gzip(data): return data[:2]==b'\x1f\x8b'

def safe_decode(data):
    for enc in ('utf-8','gbk','latin-1'):
        try: return data.decode(enc)
        except: pass
