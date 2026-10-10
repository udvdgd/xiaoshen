#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re, shutil, subprocess, tempfile
from pathlib import Path

SIG_PROM=[b"return(function(...)",b"return (function(...)",b"Welcome to LuaObfuscator"]
_HARNESS='''
local dumped=0
local real_load=load
local function cap(src,name)
  if type(src)=="string" then
    dumped=dumped+1
    local f=io.open("__OUT__/p_"..dumped..".bin","wb"); f:write(src); f:close()
    local ok,ch=pcall(real_load,src,name)
    if ok and type(ch)=="function" then pcall(ch) end
  end
  return function() end
end
load=cap; loadstring=cap
os.execute=function() return 0 end; os.exit=function() end
local fh=io.open("__SRC__","rb"); local c=fh:read("*a"); fh:close()
pcall(function() real_load(c)() end)
print(dumped)
'''

def is_prometheus(data): return any(s in data[:3000] for s in SIG_PROM)
def _find_lua():
    for n in ("lua5.3","lua5.4","lua5.2","lua"):
        if shutil.which(n): return shutil.which(n)
def decrypt(data):
    stages=[]; layers=[]; lua=_find_lua()
    if lua:
        wd=Path(tempfile.mkdtemp()); sp=wd/"s.lua"; sp.write_bytes(data)
        h=wd/"h.lua"; h.write_text(_HARNESS.replace("__OUT__",str(wd)).replace("__SRC__",str(sp)))
        try:
            p=subprocess.run([lua,str(h)],capture_output=True,timeout=60)
            stages.append((p.stdout or b"").decode().strip().splitlines()[-1])
        except Exception as e: stages.append(str(e))
        for f in sorted(wd.glob("p_*.bin"),key=lambda p:int(re.search(r"\d+",p.stem).group())):
            layers.append(f.read_bytes())
    output=layers[-1] if layers else data
    return {"type":"Prometheus","success":bool(layers),"output":output,"stages":stages,"layers":layers}
