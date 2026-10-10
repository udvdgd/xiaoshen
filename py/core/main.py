#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小神算法 - 主流程"""
from pathlib import Path
from datetime import datetime
from py.core.utils import C, looks_like_script, is_elf, is_zip, is_gzip
from py.core.decryptors import Decryptors
from py.core.so_analyzer import SOAnalyzer
from py.core.new_algorithms import try_chacha20_common, try_sm4_common
from py.plugins import registry as PLUGINS

SCRIPT_EXTS={'.js','.lua','.py','.q','.qmc','.mq','.enc','.tsproj','.luac','.hamibot','.txt','.json','.ts','.bsh','.so'}

def detect_and_decrypt(path,so_key_pool=None):
    raw=path.read_bytes()
    result={"path":path,"size":len(raw),"type":"未知","stages":[],"output":raw,"success":False}
    data=raw
    if is_gzip(data): result["type"]="GZIP"; data=Decryptors.gzip_dec(data); result["stages"].append("gunzip")
    elif is_zip(data): result["type"]="ZIP项目"; result["stages"].append("zip")
    elif is_elf(data): result["type"]="ELF/.so"; result["stages"].append("so分析")
    from py.core.wl_loader import is_wl_loader, decrypt as wl_decrypt
    if result["type"]=="未知" and is_wl_loader(data):
        wl=wl_decrypt(data); result["type"]=wl["type"]; result["stages"]+=wl["stages"]; data=wl["output"]
    from py.plugins.buxianxian import is_buxianxian, decrypt as bxx_dec
    if result["type"]=="未知" and is_buxianxian(data):
        bxx=bxx_dec(data); result["type"]="不羡仙gg-Lua"; result["stages"].append(f"RC4 {bxx['recovered']}/{bxx['total_blobs']}"); data=bxx["output"]
    from py.plugins.prometheus import is_prometheus, decrypt as prom_dec
    if result["type"]=="未知" and is_prometheus(data):
        pm=prom_dec(data); result["type"]=pm["type"]; result["stages"]+=pm["stages"]; data=pm["output"]
    if result["type"]=="未知":
        for ext,name,fn in PLUGINS.EXT_RULES:
            if path.name.lower().endswith(ext):
                result["type"]=name
                try: data=fn(data); result["stages"].append(f"{name}")
                except Exception as e: result["stages"].append(f"{name}失败")
                break
    if result["type"]=="未知":
        for sig,name,fn in PLUGINS.CONTENT_RULES:
            if sig in data[:2000]:
                result["type"]=name
                try: data=fn(data); result["stages"].append(name)
                except: pass
                break
    if not looks_like_script(data):
        for layer in range(6):
            changed=False
            for name,fn in [("b64",Decryptors.b64),("zlib",Decryptors.zlib_dec),("gzip",Decryptors.gzip_dec),("rc4",Decryptors.try_rc4_common)]:
                nxt=fn(data)
                if nxt!=data and len(nxt)>0 and looks_like_script(nxt):
                    data=nxt; result["stages"].append(name); changed=True; break
            if not changed or looks_like_script(data): break
    if not looks_like_script(data):
        nxt=Decryptors.xor_single_byte(data)
        if nxt!=data: data=nxt; result["stages"].append("xor爆破")
    if not looks_like_script(data):
        for name,fn in [("ChaCha20",try_chacha20_common),("SM4",try_sm4_common)]:
            nxt=fn(data)
            if nxt!=data and looks_like_script(nxt): data=nxt; result["stages"].append(name); break
    if not looks_like_script(data):
        from py.core.more_ciphers import try_variant_decrypt
        hit=try_variant_decrypt(data)
        if hit: data,name=hit; result["stages"].append(name)
    if so_key_pool and not looks_like_script(data):
        for sc,k,src in so_key_pool[:20]:
            for an,fn in [("RC4",Decryptors.rc4),("XOR",lambda d,kk:bytes(b^kk[i%len(kk)] for i,b in enumerate(d)))]:
                try:
                    out=fn(data,k)
                    if looks_like_script(out): data=out; result["stages"].append(f"SO密钥{an}"); break
                except: pass
    result["output"]=data
    result["success"]=looks_like_script(data) or result["type"]!="未知"
    return result

def run(target):
    root=Path(target).expanduser()
    if not root.exists(): print(f"{C.R}路径不存在{C.N}"); return
    if root.is_file(): files=[root]; out_dir=root.parent
    else:
        files=[p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SCRIPT_EXTS and "decrypted_" not in p.parts]
        out_dir=root
    if not files: print(f"{C.Y}无支持文件{C.N}"); return
    print(f"{C.B}[*] {len(files)} 个文件{C.N}\n")
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    rd=out_dir/f"decrypted_{ts}"; rd.mkdir(exist_ok=True)
    pool=[]
    for so in [f for f in files if f.suffix.lower()=='.so']:
        rep=SOAnalyzer(so).analyze()
        if rep:
            for sc,off,k in rep["key_candidates"][:15]: pool.append((sc,k,so.name))
            print(f"{C.G}[SO]{C.N} {so.name} {len(rep['key_candidates'])}候选")
    seen=set(); pool=[x for x in pool if not (x[1] in seen or seen.add(x[1]))]
    ok=fail=0
    for i,f in enumerate(files,1):
        if f.suffix.lower()=='.so': continue
        r=detect_and_decrypt(f,pool)
        rel=f.relative_to(out_dir) if f.is_relative_to(out_dir) else Path(f.name)
        op=rd/rel; op.parent.mkdir(parents=True,exist_ok=True); op.write_bytes(r["output"])
        st=f"{C.G}✓{C.N}" if r["success"] else f"{C.Y}△{C.N}"
        print(f"[{i}] {f.name} {r['type']} {'->'.join(r['stages']) or '-'} {st}")
        if r["success"]: ok+=1
        else: fail+=1
    print(f"\n{C.G}成功 {ok} 未完全 {fail}{C.N}")
    print(f"{C.B}输出 {rd}{C.N}")
