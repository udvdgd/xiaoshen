#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小神算法 - 主流程"""

import os
import sys
import re
import base64
import zipfile
from pathlib import Path
from datetime import datetime

from py.core.utils import C, looks_like_script, extract_strings, is_elf, is_zip, is_gzip
from py.core.decryptors import Decryptors
from py.core.so_analyzer import SOAnalyzer
from py.core.new_algorithms import try_chacha20_common, try_sm4_common


SCRIPT_EXTS = {'.js', '.lua', '.py', '.q', '.qmc', '.mq', '.enc',
               '.tsproj', '.luac', '.hamibot', '.txt', '.json', '.ts',
               '.bsh', '.so'}


from py.plugins import registry as PLUGINS


def detect_and_decrypt(path: Path, so_key_pool=None):
    raw = path.read_bytes()
    result = {
        "path": path, "size": len(raw), "type": "未知",
        "stages": [], "output": raw, "success": False,
    }
    data = raw

    if is_gzip(data):
        result["type"] = "GZIP"
        data = Decryptors.gzip_dec(data); result["stages"].append("gunzip")
    elif is_zip(data):
        result["type"] = "ZIP项目"
        result["stages"].append("zip(需解包)")
    elif is_elf(data):
        result["type"] = "ELF/.so"
        result["stages"].append("so分析")

    from py.core.wl_loader import is_wl_loader, decrypt as wl_decrypt
    if result["type"] == "未知" and is_wl_loader(data):
        wl = wl_decrypt(data)
        result["type"] = wl["type"]
        result["stages"] += wl["stages"]
        data = wl["output"]
        result["wl_detail"] = {
            "string_table_size": wl["string_table_size"],
            "output_is_luac52": wl["output_is_luac52"],
            "layers": len(wl["layers"]),
            "note": wl["note"],
        }

    from py.plugins.buxianxian import is_buxianxian, decrypt as bxx_dec
    if result["type"] == "未知" and is_buxianxian(data):
        bxx = bxx_dec(data)
        result["type"] = "不羡仙gg-Lua"
        result["stages"].append(f"不羡仙RC4解密 {bxx['recovered']}/{bxx['total_blobs']}串")
        data = bxx["output"]

    from py.plugins.prometheus import is_prometheus, decrypt as prom_dec
    if result["type"] == "未知" and is_prometheus(data):
        pm = prom_dec(data)
        result["type"] = pm["type"]
        result["stages"] += pm["stages"]
        data = pm["output"]

    if result["type"] == "未知":
        for ext, name, fn in PLUGINS.EXT_RULES:
            if path.name.lower().endswith(ext):
                result["type"] = name
                try:
                    data = fn(data)
                    result["stages"].append(f"{name}解密")
                except Exception as e:
                    result["stages"].append(f"{name}失败:{e}")
                break

    if result["type"] == "未知":
        for sig, name, fn in PLUGINS.CONTENT_RULES:
            if sig in data[:2000]:
                result["type"] = name
                try:
                    data = fn(data)
                    result["stages"].append(f"{name}处理")
                except: pass
                break

    if not looks_like_script(data):
        for layer in range(6):
            changed = False
            for name, fn in [("b64", Decryptors.b64), ("zlib", Decryptors.zlib_dec),
                             ("gzip", Decryptors.gzip_dec), ("rc4", Decryptors.try_rc4_common)]:
                nxt = fn(data)
                if nxt != data and len(nxt) > 0:
                    if looks_like_script(nxt):
                        data = nxt; result["stages"].append(name); changed = True
                        break
            if not changed or looks_like_script(data):
                break

    if not looks_like_script(data):
        nxt = Decryptors.xor_single_byte(data)
        if nxt != data:
            data = nxt; result["stages"].append("xor爆破")

    if not looks_like_script(data):
        for name, fn in [("ChaCha20", try_chacha20_common), ("SM4", try_sm4_common)]:
            nxt = fn(data)
            if nxt != data and looks_like_script(nxt):
                data = nxt; result["stages"].append(name); break

    if not looks_like_script(data):
        from py.core.more_ciphers import try_variant_decrypt
        hit = try_variant_decrypt(data)
        if hit:
            data, name = hit
            result["stages"].append(name)

    if so_key_pool and not looks_like_script(data):
        for sc, k, src in so_key_pool[:20]:
            for algo_name, fn in [("RC4", Decryptors.rc4),
                                  ("XOR", lambda d, kk: bytes(b ^ kk[i % len(kk)] for i, b in enumerate(d)))]:
                try:
                    out = fn(data, k)
                    if looks_like_script(out):
                        data = out
                        result["stages"].append(f"SO密钥[{algo_name}:{k.decode('utf-8','ignore')}@{src}]")
                        break
                except: pass

    result["output"] = data
    result["success"] = looks_like_script(data) or result["type"] not in ("未知",)
    return result


def run(target: str):
    root = Path(target).expanduser()
    if not root.exists():
        print(f"{C.R}[!] 路径不存在: {root}{C.N}")
        return

    if root.is_file():
        files = [root]; out_dir = root.parent
    else:
        files = [p for p in root.rglob("*")
                 if p.is_file() and p.suffix.lower() in SCRIPT_EXTS
                 and "decrypted_" not in p.parts]
        out_dir = root

    if not files:
        print(f"{C.Y}[!] 未发现支持的文件{C.N}")
        return

    print(f"{C.B}[*] 发现 {len(files)} 个文件{C.N}\n")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = out_dir / f"decrypted_{ts}"
    result_dir.mkdir(exist_ok=True)

    so_files = [f for f in files if f.suffix.lower() == '.so']
    so_key_pool = []
    for so in so_files:
        a = SOAnalyzer(so)
        rep = a.analyze()
        if rep:
            for sc, off, k in rep["key_candidates"][:15]:
                so_key_pool.append((sc, k, so.name))
            rep_txt = [f"SO 报告: {so}", f"架构: {rep['arch']}",
                       f"算法命中: {[n for n,_ in rep['algo_hits']]}",
                       f"JNI: {[s.decode('utf-8','ignore') for _,s in rep['jni_funcs'][:10]]}",
                       "", "密钥候选:"]
            for sc, off, k in rep["key_candidates"][:15]:
                rep_txt.append(f"  {sc:>3} @0x{off:X}  {k.decode('utf-8','ignore')}")
            (result_dir / (so.stem + "_so_report.txt")).write_text("\n".join(rep_txt), encoding='utf-8')
            print(f"{C.G}[SO]{C.N} {so.name} -> {len(rep['key_candidates'])} 密钥候选")

    seen = set()
    so_key_pool = [(sc, k, src) for sc, k, src in so_key_pool
                   if not (k in seen or seen.add(k))]

    ok = fail = 0
    for i, f in enumerate(files, 1):
        if f.suffix.lower() == '.so':
            continue
        r = detect_and_decrypt(f, so_key_pool)
        rel = f.relative_to(out_dir) if f.is_relative_to(out_dir) else Path(f.name)
        out_path = result_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(r["output"])
        status = f"{C.G}✓{C.N}" if r["success"] else f"{C.Y}△{C.N}"
        print(f"{C.W}[{i}]{C.N} {f.name}  {C.P}{r['type']}{C.N}  "
              f"{C.C}{'->'.join(r['stages']) or '无操作'}{C.N}  {status}")
        if r["success"]: ok += 1
        else: fail += 1

    print(f"\n{C.G}完成: 成功 {ok}, 未完全解密 {fail}{C.N}")
    print(f"{C.B}输出: {result_dir}{C.N}")
