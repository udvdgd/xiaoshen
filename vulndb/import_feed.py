#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""漏洞情报导入器：把官方公开 CVE 数据规整进小神漏洞库。
  python3 import_feed.py nvd nvdcve-1.1-2024.json
  python3 import_feed.py generic my_list.json
输出 vulns_full.json（query.py 自动优先读取）。仅结构化整理，不含利用代码。
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "vulns_full.json")


def pick_desc(entries):
    for d in entries or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return (entries[0].get("value", "") if entries else "")[:300]


def pick_severity(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            d = metrics[key][0].get("cvssData", {})
            return (d.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "").lower()
    return "unknown"


def from_nvd(path):
    data = json.load(open(path, encoding="utf-8"))
    out = []
    for c in data.get("vulnerabilities", []):
        item = c.get("cve", {})
        cid = item.get("id", "")
        if not cid:
            continue
        refs = [r.get("url", "") for r in item.get("references", {}).get("reference_data", [])]
        out.append({
            "id": cid,
            "name": "",
            "product": "见描述",
            "affected": "见描述",
            "severity": pick_severity(item.get("metrics", {})),
            "summary": pick_desc(item.get("descriptions", [])),
            "detect": "依据厂商/产品公告核对版本",
            "remediate": "升级/缓解，参考官方公告",
            "ref": refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cid}",
        })
    return out


def from_generic(path):
    raw = json.load(open(path, encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("cves", [])
    out = []
    for it in raw:
        out.append({
            "id": it.get("id") or it.get("cve_id") or "",
            "name": it.get("name", ""),
            "product": it.get("product", ""),
            "affected": it.get("affected", ""),
            "severity": it.get("severity", "unknown"),
            "summary": it.get("summary") or it.get("description", ""),
            "detect": it.get("detect", "见公告"),
            "remediate": it.get("remediate", "见公告"),
            "ref": it.get("ref") or (it.get("references", [""])[0] if it.get("references") else ""),
        })
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__); return
    kind, path = sys.argv[1], sys.argv[2]
    rows = from_nvd(path) if kind == "nvd" else from_generic(path) if kind == "generic" else None
    if rows is None:
        print("类型必须是 nvd 或 generic"); return
    seed = []
    sp = os.path.join(HERE, "vulns.json")
    if os.path.exists(sp):
        seed = json.load(open(sp, encoding="utf-8")).get("cves", [])
    merged = seed + rows
    json.dump({"source": "xiaoshen vulndb", "count": len(merged), "cves": merged},
              open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"[+] 导入 {len(rows)} + 精选 {len(seed)} = {len(merged)} 条 -> vulns_full.json")


if __name__ == "__main__":
    main()
