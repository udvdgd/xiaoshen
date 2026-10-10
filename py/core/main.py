#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小神算法 - 主流程"""
import os
from pathlib import Path
from datetime import datetime
from py.core.utils import C, looks_like_script
from py.core.decryptors import Decryptors
from py.core.so_analyzer import SOAnalyzer
from py.core.new_algorithms import try_chacha20_common, try_sm4_common
SCRIPT_EXTS={'.js','.lua','.py','.q','.qmc','.mq','.enc','.tsproj','.luac','.hamibot','.txt','.json','.ts','.bsh','.so'}
from py.plugins import registry as PLUGINS

def detect_and_decrypt(path, so_key_pool=None, user_key=None):
    raw=path.read_bytes()
    result={"path":path,"size":len(raw),"type":"未知","stages":[],"output":raw,"success":False}
    data=raw
    # 0. XSCipher 自研容器优先
    if raw[:4] in (b"XSN1",b"XSN2"):
        result["type"]="XSCipher"+("v2" if raw[:4]==b"XSN2" else "v1")
        if user_key is None:
            result["stages"].append("XSCipher需密钥"); return result
        try:
            from py.core.xshen_algorithms import XSCipher, XSCipherV2
            core=XSCipherV2 if raw[:4]==b"XSN2" else XSCipher
            data=core.decrypt(raw,user_key)
            result["stages"].append("XSCipher解密"); result["output"]=data; result["success"]=True; return result
        except Exception as e:
            result["stages"].append(f"XSCipher失败:{e}"); return result
    # 1. magic
    from py.core.utils import is_gzip, is_zip, is_elf
    if is_gzip(data): result["type"]="GZIP"; data=Decryptors.gzip_dec(data); result["stages"].append("gunzip")
    elif is_zip(data): result["type"]="ZIP项目"; result["stages"].append("zip(需解包)")
    elif is_elf(data): result["type"]="ELF/.so"; result["stages"].append("so分析")
    # 1.5 wl_loader
    from py.core.wl_loader import is_wl_loader, decrypt as wl_decrypt
    if result["type"]=="未知" and is_wl_loader(data):
        wl=wl_decrypt(data); result["type"]=wl["type"]; result["stages"]+=wl["stages"]; data=wl["output"]
    # 1.6 不羡仙
    from py.plugins.buxianxian import is_buxianxian, decrypt as bxx_dec
    if result["type"]=="未知" and is_buxianxian(data):
        bxx=bxx_dec(data); result["type"]="不羡仙gg-Lua"; result["stages"].append(f"不羡仙RC4 {bxx['recovered']}/{bxx['total_blobs']}"); data=bxx["output"]
    # 1.7 Prometheus
    from py.plugins.prometheus import is_prometheus, decrypt as prom_dec
    if result["type"]=="未知" and is_prometheus(data):
        pm=prom_dec(data); result["type"]=pm["type"]; result["stages"]+=pm["stages"]; data=pm["output"]
    # 2. 插件
    if result["type"]=="未知":
        for ext,name,fn in PLUGINS.EXT_RULES:
            if path.name.lower().endswith(ext):
                result["type"]=name
                try: data=fn(data); result["stages"].append(f"{name}解密")
                except Exception as e: result["stages"].append(f"{name}失败:{e}")
                break
    if result["type"]=="未知":
        for sig,name,fn in PLUGINS.CONTENT_RULES:
            if sig in data[:2000]:
                try: data=fn(data); result["stages"].append(f"{name}处理")
                except: pass
                break
    # 3. 通用流水线
    if not looks_like_script(data):
        for layer in range(6):
            changed=False
            for name,fn in [("b64",Decryptors.b64),("zlib",Decryptors.zlib_dec),("gzip",Decryptors.gzip_dec),("rc4",Decryptors.try_rc4_common)]:
                nxt=fn(data)
                if nxt!=data and len(nxt)>0 and looks_like_script(nxt):
                    data=nxt; result["stages"].append(name); changed=True; break
            if not changed or looks_like_script(data): break
    # 4. XOR 爆破
    if not looks_like_script(data):
        nxt=Decryptors.xor_single_byte(data)
        if nxt!=data: data=nxt; result["stages"].append("xor爆破")
    # 4.5 新型算法
    if not looks_like_script(data):
        for name,fn in [("ChaCha20",try_chacha20_common),("SM4",try_sm4_common)]:
            nxt=fn(data)
            if nxt!=data and looks_like_script(nxt): data=nxt; result["stages"].append(name); break
    # 4.6 壳变形
    if not looks_like_script(data):
        from py.core.more_ciphers import try_variant_decrypt
        hit=try_variant_decrypt(data)
        if hit: data,name=hit; result["stages"].append(name)
    # 5. SO 密钥联动
    if so_key_pool and not looks_like_script(data):
        for sc,k,src in so_key_pool[:20]:
            try:
                out=Decryptors.rc4(data,k)
                if looks_like_script(out): data=out; result["stages"].append(f"SO密钥RC4@{src}"); break
            except: pass
    result["output"]=data
    result["success"]=looks_like_script(data) or result["type"] not in ("未知",)
    return result

def run(target):
    root=Path(target).expanduser()
    if not root.exists(): print(f"{C.R}[!] 路径不存在: {root}{C.N}"); return
    if root.is_file(): files=[root]; out_dir=root.parent
    else:
        files=[p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SCRIPT_EXTS and "decrypted_" not in p.parts]; out_dir=root
    if not files: print(f"{C.Y}[!] 未发现支持的文件{C.N}"); return
    print(f"{C.B}[*] 发现 {len(files)} 个文件{C.N}\n")
    ts=datetime.now().strftime("%Y%m%d_%H%M%S"); result_dir=out_dir/f"decrypted_{ts}"; result_dir.mkdir(exist_ok=True)
    so_files=[f for f in files if f.suffix.lower()=='.so']; so_key_pool=[]
    for so in so_files:
        rep=SOAnalyzer(so).analyze()
        if rep:
            for sc,off,k in rep["key_candidates"][:15]: so_key_pool.append((sc,k,so.name))
    seen=set(); so_key_pool=[(sc,k,s) for sc,k,s in so_key_pool if not(k in seen or seen.add(k))]
    xs=[f for f in files if f.suffix.lower()!='.so' and f.read_bytes()[:4] in (b"XSN1",b"XSN2")]
    user_key=None
    if xs:
        print(f"{C.P}[i] {len(xs)} 个 XSCipher 文件{C.N}")
        ans=input(f"{C.C}[?] XSCipher 密钥(留空跳过):{C.N}\n> ").strip()
        if ans: user_key=ans.encode()
    ok=fail=0
    for i,f in enumerate(files,1):
        if f.suffix.lower()=='.so': continue
        r=detect_and_decrypt(f,so_key_pool,user_key)
        rel=f.relative_to(out_dir) if f.is_relative_to(out_dir) else Path(f.name)
        outp=result_dir/rel; outp.parent.mkdir(parents=True,exist_ok=True); outp.write_bytes(r["output"])
        st=f"{C.G}✓{C.N}" if r["success"] else f"{C.Y}△{C.N}"
        print(f"{C.W}[{i}]{C.N} {f.name} {C.P}{r['type']}{C.N} {C.C}{'->'.join(r['stages']) or '无'}{C.N} {st}")
        if r["success"]:ok+=1
        else:fail+=1
    print(f"\n{C.G}完成: 成功 {ok}, 未完全 {fail}{C.N}\n{C.B}输出: {result_dir}{C.N}")
