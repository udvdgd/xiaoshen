#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""渐进式智能爆破器 (Python 兜底版)"""
import itertools
from py.core.decryptors import Decryptors
from py.core.utils import C

COMMON_WORDS=[b"123456",b"password",b"admin",b"autojs",b"script",b"touchsprite",b"hamibot",b"qmacro",b"key",b"test",b"root",b"abc123",b"xiaoshen",b"auto",b"pro",b"vip",b"android",b"mobile",b"game",b"cheat",b"hack",b"12345678",b"abcdef",b"qwerty"]
CHARSETS=["0123456789","abcdefghijklmnopqrstuvwxyz","0123456789abcdef","abcdefghijklmnopqrstuvwxyz0123456789","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]

def score(data):
    if len(data)<4: return 0
    head=data[:500]
    kws=[b"function",b"var ",b"import",b"local ",b"require",b"console.",b"print(",b"return ",b"//",b"#",b"toast(",b"device.",b"if ",b"for ",b"while",b"auto."]
    s=sum(head.count(k)*10 for k in kws)
    pr=sum(1 for b in head if 0x20<=b<=0x7e or b in (9,10,13))
    s+=(pr*5)//max(1,len(head)); return s

def smart_crack(data,algo="rc4",max_len=5):
    best_score=0; best_key=None; tried=0
    def try_key(key):
        nonlocal best_score,best_key,tried
        tried+=1
        try:
            out=Decryptors.rc4(data,key) if algo=="rc4" else bytes(b^key[i%len(key)] for i,b in enumerate(data))
            s=score(out)
            if s>best_score:
                best_score=s; best_key=key
                print(f"\r{C.C}[*] {tried} key={key} score={s}{C.N}",end="",flush=True)
            return s>=80
        except: return False
    print(f"{C.B}[Phase 1] 常见词{C.N}")
    for w in COMMON_WORDS:
        if try_key(w): break
    if best_score<50:
        for ci,cs in enumerate(CHARSETS):
            print(f"\n{C.B}[Phase 2.{ci}] {cs}{C.N}")
            for length in range(1,max_len+1):
                if best_score>=50: break
                for combo in itertools.product(cs,repeat=length):
                    if try_key("".join(combo).encode()): break
                if best_score>=50: break
            if best_score>=50: break
    print(f"\n\n{C.G}完成 尝试{tried} 最佳{best_key} score={best_score}{C.N}")
    if best_key and best_score>=10:
        out=Decryptors.rc4(data,best_key) if algo=="rc4" else bytes(b^best_key[i%len(best_key)] for i,b in enumerate(data))
        return out,best_key
    return None,best_key
