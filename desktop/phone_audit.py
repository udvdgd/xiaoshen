#!/usr/bin/env python3
# phone_audit.py USB 连机只读安全巡检（防御侧）
# 通过 adb 只读读取补丁级别，对照漏洞库报告风险；不 root/不利用/不改系统。
# 用法：adb devices 看到设备后运行 python3 phone_audit.py
import re, subprocess, datetime

RULES = [
    ("2026-10-01", "2026-10 批次严重系统提权 55269/55280/58835/58880"),
    ("2026-09-01", "System 整数溢出提权 CVE-2026-49927"),
]

def sh(a):
    try: return subprocess.run(a, capture_output=True, text=True, timeout=15).stdout.strip()
    except FileNotFoundError: return ""

def gp(k): return sh(["adb", "shell", "getprop", k]).strip()

def pd(s):
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s or "")
    if not m: return None
    try: return datetime.date(int(m[1]), int(m[2]), int(m[3]))
    except ValueError: return None

lines = [l for l in sh(["adb","devices"]).splitlines()[1:] if l.strip() and "device" in l]
if not lines:
    print("[!] 未检测到 adb 设备：确认 USB 已连、USB 调试已开、已授权。")
else:
    print("="*52); print(" 小神 · 手机 USB 只读巡检（不 root/不利用）"); print("="*52)
    print(" 品牌/型号 :", gp("ro.product.brand"), gp("ro.product.model"))
    print(" Android  :", gp("ro.build.version.release"))
    print(" 补丁级别  :", gp("ro.build.version.security_patch"))
    print("-"*52)
    p = pd(gp("ro.build.version.security_patch"))
    if not p:
        print("[?] 读不到补丁日期，无法判定。")
    else:
        risk = False
        for th, d in RULES:
            if p < pd(th): risk = True; print("[!] 可能中招(早于 %s): %s" % (th, d))
            else: print("[OK] %s 之前问题已修复" % th)
        print("-"*52)
        print("结论：" + ("补丁偏旧，建议系统更新；修补前别在该机登录银行/支付。" if risk else "补丁在已知提权批次之后，本库范围内未见高危敞口。"))
