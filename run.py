#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小神算法 · 大型脚本加解密工具 (企业版)
=====================================
启动后逐字显示"小神官方", 然后菜单:
  1) 解密  2) 加密
加密为独家多层算法, 支持 Lua / JS / Python / Shell, 填入手机路径自动列出脚本选择。
"""
import sys
import os
import time
import glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from py.core.utils import C


SCRIPT_EXTS = ("*.lua", "*.js", "*.py", "*.ts", "*.sh")


def typewriter(text: str, delay: float = 0.12, color=C.P):
    for ch in text:
        print(color + ch + C.N, end="", flush=True)
        time.sleep(delay)
    print()


def show_banner():
    print(f"{C.BOLD}")
    print("  ╔══════════════════════════════════╗")
    typewriter("  小 神 官 方", 0.15, C.P)
    print("  ╚══════════════════════════════════╝" + C.N)
    print(f"{C.C}  Xiaoshen Official · 企业级脚本加解密套件{C.N}")
    print()


def list_scripts(dirpath: str) -> list:
    files = []
    for ext in SCRIPT_EXTS:
        files += glob.glob(os.path.join(dirpath, ext))
    return sorted(set(os.path.normpath(f) for f in files))


def do_decrypt():
    path = input(f"{C.C}[?] 输入要解密的文件或目录路径:{C.N}\n> ").strip().strip("'\"")
    if not path:
        print(f"{C.Y}[!] 未输入路径{C.N}")
        return
    from py.core.main import run as run_main
    run_main(path)


def do_encrypt():
    path = input(f"{C.C}[?] 输入脚本所在文件夹(手机路径):{C.N}\n> ").strip().strip("'\"")
    if not path:
        path = os.getcwd()
    if not os.path.isdir(path):
        print(f"{C.Y}[!] 目录不存在: {path}{C.N}")
        return
    files = list_scripts(path)
    if not files:
        print(f"{C.Y}[!] 该目录没找到 .lua/.js/.py/.sh 脚本{C.N}")
        return

    print(f"\n{C.BOLD}  检测到 {len(files)} 个脚本:{C.N}")
    print(f"  {'序号':<6}{'类型':<8}{'大小':<10}文件")
    print("  " + "-" * 50)
    for i, f in enumerate(files, 1):
        ext = os.path.splitext(f)[1].lstrip(".")
        size = os.path.getsize(f)
        print(f"  {i:<6}{ext:<8}{size:<10}{os.path.basename(f)}")
    print(f"  {'a':<6}{'全部'}")

    sel = input(f"\n{C.C}[?] 输入要加密的序号(多个用逗号, a=全部):{C.N}\n> ").strip().lower()
    from py.core.encryptor import encrypt_file
    targets = []
    if sel == "a":
        targets = files
    else:
        try:
            for n in sel.replace("，", ",").split(","):
                n = n.strip()
                if n.isdigit():
                    idx = int(n) - 1
                    if 0 <= idx < len(files):
                        targets.append(files[idx])
        except Exception:
            pass

    if not targets:
        print(f"{C.Y}[!] 没选到有效脚本{C.N}")
        return

    for f in targets:
        try:
            new, kind = encrypt_file(f)
            out = f + ".xsn"
            with open(out, "w", encoding="utf-8") as fp:
                fp.write(new)
            print(f"{C.G}[+] 加密成功 {kind}: {os.path.basename(f)} -> {os.path.basename(out)}{C.N}")
            print(f"     输出 {len(new)} 字节, 已用最高企业加密(独家算法), 可直接运行")
        except Exception as e:
            print(f"{C.Y}[!] 加密失败 {os.path.basename(f)}: {e}{C.N}")


def do_enterprise_enc():
    import getpass
    path = input(f"{C.C}[?] 输入要加密的文件路径:{C.N}\n> ").strip().strip("'\"")
    if not os.path.isfile(path):
        print(f"{C.Y}[!] 文件不存在{C.N}")
        return
    pw = getpass.getpass(f"{C.C}[?] 设置加密口令(输入时不显示):{C.N} ")
    if len(pw) < 6:
        print(f"{C.Y}[!] 口令至少 6 位{C.N}")
        return
    from py.core.enterprise_crypto import encrypt_file
    out = encrypt_file(path, pw)
    print(f"{C.G}[+] 企业级加密完成: {os.path.basename(out)}{C.N}")
    print(f"     AES-256-GCM + PBKDF2(60万次), 密钥只在你口令里, 无口令不可破解")


def main():
    show_banner()
    while True:
        print(f"""
{C.BOLD}  ====== 菜单 ======{C.N}
  {C.P}1{C.N}) 解密
  {C.P}2{C.N}) 加密 (免密钥·深度混淆壳)
  {C.P}3{C.N}) 企业级加密 (AES-256-GCM·口令·真不可破)
  {C.P}0{C.N}) 退出
""")
        c = input(f"{C.C}[?] 请选择:{C.N} ").strip()
        if c == "1":
            do_decrypt()
        elif c == "2":
            do_encrypt()
        elif c == "3":
            do_enterprise_enc()
        elif c == "0":
            print(f"{C.P}  再见!{C.N}")
            break
        else:
            print(f"{C.Y}[!] 无效选择{C.N}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[已退出]{C.N}")
