#!/usr/bin/env python3
# selfcheck.py — 本机安全自检（防御向，只读）
# 检查监听端口/SSH弱配置/防火墙/自动更新；只读本机状态，不扫描外部目标。
import os, subprocess, platform

def run(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""

def ok(m): print(f"  [OK] {m}")
def warn(m): print(f"  [!]  {m}")
def info(m): print(f"  [i]  {m}")

def listening_ports():
    out = run("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
    return [l for l in out.splitlines() if "LISTEN" in l]

def ssh_check():
    issues = []
    for line in run("cat /etc/ssh/sshd_config 2>/dev/null").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if line.lower().startswith("permitrootlogin yes"):
            issues.append("PermitRootLogin yes（建议改 prohibit-password）")
        if line.lower().startswith("permitemptypasswords yes"):
            issues.append("PermitEmptyPasswords yes（建议改 no）")
    return issues

def firewall_check():
    if run("command -v ufw"):
        return "inactive" not in run("ufw status 2>/dev/null").lower()
    if run("command -v firewall-cmd"):
        return "running" in run("firewall-cmd --state 2>/dev/null").lower()
    return None

def main():
    print("="*54); print(" 小神 · 本机安全自检（只读 / 防御向）"); print("="*54)
    info(f"系统: {platform.system()} {platform.release()} ({platform.node()})")
    print("\n[1] 对外监听端口")
    ports = listening_ports()
    if not ports:
        ok("未发现监听端口")
    else:
        wan = [p for p in ports if "0.0.0.0" in p or ":::" in p]
        for p in wan:
            warn("对外开放: " + " ".join(p.split()[:4]))
        if not wan: ok("监听端口均绑定在本机/内网")
        info(f"共 {len(ports)} 个监听，对外 {len(wan)} 个")
    print("\n[2] SSH 弱配置")
    iss = ssh_check()
    if not iss: ok("未发现明显 SSH 弱配置（或无 sshd）")
    else:
        for i in iss: warn(i)
    print("\n[3] 防火墙")
    fw = firewall_check()
    if fw is True: ok("系统防火墙已启用")
    elif fw is False: warn("系统防火墙未启用")
    else: info("未检测到常见防火墙（云主机用云控制台安全组）")
    print("\n[4] 自动更新")
    if run("command -v unattended-upgrade") or os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
        ok("存在自动更新配置")
    else: info("未检测到自动更新，建议定期手动更新")
    print("\n结论：本机粗检，不替代专业渗透测试；[!] 项请逐项加固。")

if __name__ == "__main__":
    main()
