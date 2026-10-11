#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安卓(免 root) 权限自查：列出已装应用申请的危险权限与可疑组合。
Termux / adb shell 运行。无 root 仅读 shell 可见信息。
  python3 android_perm.py suspicious
  python3 android_perm.py <包名>
"""
import subprocess, sys, re

DANGEROUS = {
    "android.permission.READ_CONTACTS": "通讯录",
    "android.permission.WRITE_CONTACTS": "写通讯录",
    "android.permission.READ_SMS": "读短信",
    "android.permission.SEND_SMS": "发短信",
    "android.permission.CALL_PHONE": "拨打电话",
    "android.permission.READ_CALL_LOG": "通话记录",
    "android.permission.CAMERA": "相机",
    "android.permission.RECORD_AUDIO": "麦克风",
    "android.permission.ACCESS_FINE_LOCATION": "精确定位",
    "android.permission.ACCESS_COARSE_LOCATION": "模糊定位",
    "android.permission.READ_EXTERNAL_STORAGE": "读存储",
    "android.permission.WRITE_EXTERNAL_STORAGE": "写存储",
    "android.permission.READ_CALENDAR": "日历",
    "android.permission.SYSTEM_ALERT_WINDOW": "悬浮窗",
    "android.permission.REQUEST_INSTALL_PACKAGES": "装其它应用",
    "android.permission.QUERY_ALL_PACKAGES": "查询所有应用",
}
SUSPECT = [("内容类应用却同时要短信+通讯录+麦克风",
            {"android.permission.READ_SMS", "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO"})]


def sh(c):
    try:
        return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ""


def list_pkgs():
    return [l.replace("package:", "").strip() for l in sh("pm list packages").splitlines() if l.startswith("package:")]


def perms_of(pkg):
    return set(re.findall(r"android\.permission\.[A-Z_]+", sh(f"dumpsys package {pkg}")))


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd = sys.argv[1]
    if cmd == "suspicious" or len(sys.argv) < 3:
        pkgs = list_pkgs()
        print(f"共 {len(pkgs)} 个包（无 root 时数据有限）...\n")
        hits = 0
        for p in pkgs:
            ps = perms_of(p)
            flags = sorted({DANGEROUS[x] for x in ps if x in DANGEROUS})
            for why, combo in SUSPECT:
                if combo.issubset(ps):
                    print(f"[!] {p}: {why}"); hits += 1
            if len(flags) >= 5:
                print(f"[?] {p}: {len(flags)} 类敏感权限 -> {', '.join(flags)}")
        if hits == 0:
            print("未命中可疑组合（仅基础扫描）")
        return
    ps = perms_of(cmd)
    print(f"== {cmd} ==")
    for x in sorted(ps):
        print("  " + x + ("  高敏" if x in DANGEROUS else ""))


if __name__ == "__main__":
    main()
