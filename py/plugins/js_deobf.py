#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JS 反混淆"""
import re, base64

def decrypt(data):
    txt=data.decode('utf-8',errors='ignore')
    m=re.search(r"(?:var|let|const)\s+(_0x\w+)\s*=\s*\[(.*?)\];",txt,re.S)
    if m:
        body=m.group(2)
        strs=re.findall(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"",body)
        decoded=[s[0] or s[1] for s in strs]
        out="// [小神] 混淆字符串数组:\n"
        for i,s in enumerate(decoded): out+=f"// [{i}] {s}\n"
        return (out+"\n"+txt).encode('utf-8',errors='ignore')
    if "ﾟωﾟ" in txt:
        return ("// [小神] AAEncode, 用 js-beautify 还原\n").encode()+data
    return data
