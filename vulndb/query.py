#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小神漏洞库查询（只读）：list / search / show。
  python3 query.py list
  python3 query.py search log4j
  python3 query.py show CVE-2021-44228
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load():
    full = os.path.join(HERE, "vulns_full.json")
    path = full if os.path.exists(full) else os.path.join(HERE, "vulns.json")
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)["cves"]
    lpe = os.path.join(HERE, "android_lpe.json")
    if os.path.exists(lpe):
        with open(lpe, encoding="utf-8") as f:
            rows = rows + json.load(f)["cves"]
    print(f"(共 {len(rows)} 条)\n")
    return rows


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
