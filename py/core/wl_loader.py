#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wl_loader VM 型 Lua 保护壳专用解密器"""
import re, shutil, subprocess, tempfile
from pathlib import Path

SIG=[b"[wl_loader]",b"Decompiled by RUA",b"wlloadP"]
_TBL_RE=re.compile(rb"\[\s*(\d+)\s*\]\s*=\s*\"((?:[^\"\\]|\\.)*)\"",re.S)

def is_wl_loader(data):
    hits=sum(1 for s in SIG if s in data[:200000])
    return hits>=2 or b"wl_loader" in data[:4000]

def _lua_unescape(s):
    out=bytearray(); i=0; n=len(s)
    while i<n:
        c=s[i]
        if c==0x5C:
            i+=1
            if i>=n: break
            d=s[i]
            if 0x30<=d<=0x39:
                num=bytes([d]); j=i+1
                while j<n and 0x30<=s[j]<=0x39 and len(num)<3: num+=bytes([s[j]]); j+=1
                out.append(int(num)&0xFF); i=j; continue
            mp={110:10,116:9,114:13,48:0,34:34,92:92,97:7,98:8,102:12,118:11}
            out.append(mp.get(d,d)); i+=1
        else: out.append(c); i+=1
    return bytes(out)

def extract_string_table(data):
    t={}
    for m in _TBL_RE.finditer(data): t[int(m.group(1))]=_lua_unescape(m.group(2))
    return t

_HARNESS=r'''
local band,bor,bxor=function(a,b) return a&b end,function(a,b) return a|b end,function(a,b) return a~b end
bit32={band=band,bor=bor,bxor=bxor,bnot=function(a) return ~a end,lshift=function(a,n) return (a<<n)&0xFFFFFFFF end,rshift=function(a,n) return a>>n end,arshift=function(a,n) return a>>n end}
bit=bit32
local real_load=load; local depth=0
local function dump(src,name)
  depth=depth+1
  if type(src)=="string" then
    local f=io.open(("__O__/layer_%d.bin"):format(depth),"wb"); f:write(src); f:close()
    local ok,ch=pcall(real_load,src,name)
    if ok and type(ch)=="function" then pcall(ch) end
  end
  return function() end
end
load=dump; loadstring=dump
os.execute=function() return 0 end; os.exit=function() end
local fh=io.open("__S__","rb"); local code=fh:read("*a"); fh:close()
pcall(function() real_load(code)() end)
print(depth)
'''

def _find_lua():
    for n in ("lua5.3","lua5.4","lua5.2","lua"):
        if shutil.which(n): return shutil.which(n)

def dynamic_dump(data):
    lua=_find_lua(); res={"layers":[],"lua":lua,"note":""}
    if not lua: res["note"]="无 lua 运行时"; return res
    wd=Path(tempfile.mkdtemp(prefix="wl_")); sp=wd/"s.lua"; sp.write_bytes(data)
    h=wd/"h.lua"; h.write_text(_HARNESS.replace("__O__",str(wd)).replace("__S__",str(sp)))
    try: subprocess.run([lua,str(h)],capture_output=True,timeout=60)
    except Exception: res["note"]="超时"; return res
    for f in sorted(wd.glob("layer_*.bin"),key=lambda p:int(re.search(r"\d+",p.stem).group())):
        res["layers"].append(f.read_bytes())
    res["note"]=f"dump {len(res['layers'])} 层"
    return res

def decrypt(data):
    stages=["识别 wl_loader"]
    tbl=extract_string_table(data); stages.append(f"串表 {len(tbl)} 项")
    main_blob=max(tbl.items(),key=lambda kv:len(kv[1]),default=(0,b""))[1]
    dyn=dynamic_dump(data); stages.append(dyn["note"]); layers=dyn["layers"]
    output=layers[-1] if layers else main_blob
    is_luac=output[:4]==b"\x1bLua"
    return {"type":"wl_loader","success":bool(layers) or is_luac or bool(main_blob),"output":output,"stages":[s for s in stages if s],"layers":layers,"string_table_size":len(tbl),"output_is_luac52":is_luac and output[4:5]==b"\x52","note":"内层 Lua5.2 字节码" if is_luac else "回退静态提取"}
