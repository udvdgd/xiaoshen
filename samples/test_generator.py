#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成测试样本: 用各种算法加密示例脚本, 验证解密器"""
import os,sys,base64,zlib
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from py.core.decryptors import Decryptors
SAMPLE=b'function main(){\n  auto.waitFor();\n  toast("hello xiaoshen");\n  var x = device.width;\n  print(x);\n}'
OUT=os.path.join(os.path.dirname(__file__),"test_samples"); os.makedirs(OUT,exist_ok=True)
open(os.path.join(OUT,"plain.js"),"wb").write(SAMPLE)
open(os.path.join(OUT,"b64.js"),"wb").write(base64.b64encode(SAMPLE))
open(os.path.join(OUT,"zlib_b64.js"),"wb").write(base64.b64encode(zlib.compress(SAMPLE)))
open(os.path.join(OUT,"xor_single.js"),"wb").write(bytes(b^0x5A for b in SAMPLE))
open(os.path.join(OUT,"rc4_autojs.js"),"wb").write(Decryptors.rc4(SAMPLE,b"autojs"))
open(os.path.join(OUT,"autojs.enc"),"wb").write(bytes(b^b"autojs"[i%6] for i,b in enumerate(SAMPLE)))
table=[0x0A,0x1B,0x3C,0x5D,0x7E,0x9F,0xA0,0xC1]
open(os.path.join(OUT,"test.q"),"wb").write(bytes(b^table[i%8] for i,b in enumerate(SAMPLE)))
print("samples in",OUT)
for f in sorted(os.listdir(OUT)): print(" ",f)
