#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小神漏洞库查询 — 只读检索公开 CVE 防御侧信息（不含利用代码）。
  python3 query.py list
  python3 query.py search log4j
  python3 query.py show CVE-2021-44228
"""
import json, os, sys
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulns.json")

def load():
    with open(DB, encoding="utf-8") as f:
        return json.load(f)["cves"]

def row(v):
    return f"{v['id']:18} [{v['severity']:8}] {v['product']:22} {v['name']}"

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd, *rest = sys.argv[1:]
    kw = " ".join(rest).lower()
    db = load()
    if cmd == "list":
        for v in db:
            print(row(v))
        print(f"\n共 {len(db)} 条")
    elif cmd == "search":
        hits = [v for v in db if kw in json.dumps(v, ensure_ascii=False).lower()]
        if not hits:
            print("无匹配"); return
        for v in hits:
            print(row(v))
        print(f"\n命中 {len(hits)} 条")
    elif cmd == "show":
        for v in db:
            if v["id"].lower() == kw:
                for k in ("id", "name", "product", "affected", "severity", "summary", "detect", "remediate", "ref"):
                    print(f"{k:10}: {v.get(k,'')}")
                return
        print("未找到")
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
