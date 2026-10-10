#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小神算法 · 大型脚本加解密工具 (企业版)
启动逐字显示"小神官方", 菜单:
  1 解密 | 2 免密钥混淆加密 | 3 企业级 AES-GCM | 4 XSCipher 自研v2加密
"""
import sys,os,time,glob
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from py.core.utils import C
SCRIPT_EXTS=("*.lua","*.js","*.py","*.ts","*.sh")

def typewriter(text,delay=0.12,color=C.P):
    for ch in text: print(color+ch+C.N,end="",flush=True); time.sleep(delay)
    print()
def show_banner():
    print(C.BOLD); print("  ╔══════════════════════════════════╗")
    typewriter("  小 神 官 方",0.15,C.P)
    print("  ╚══════════════════════════════════╝"+C.N)
    print(f"{C.C}  Xiaoshen Official · 企业级脚本加解密套件{C.N}\n")
def list_scripts(d):
    f=[]
    for e in SCRIPT_EXTS: f+=glob.glob(os.path.join(d,e))
    return sorted(set(os.path.normpath(x) for x in f))
def do_decrypt():
    path=input(f"{C.C}[?] 输入要解密的文件或目录路径:{C.N}\n> ").strip().strip("'\"")
    if not path: print(f"{C.Y}[!] 未输入路径{C.N}"); return
    from py.core.main import run
    run(path)
def do_encrypt():
    path=input(f"{C.C}[?] 输入脚本所在文件夹(手机路径):{C.N}\n> ").strip().strip("'\"")
    if not path: path=os.getcwd()
    if not os.path.isdir(path): print(f"{C.Y}[!] 目录不存在{C.N}"); return
    files=list_scripts(path)
    if not files: print(f"{C.Y}[!] 未找到 .lua/.js/.py 脚本{C.N}"); return
    print(f"\n{C.BOLD}  检测到 {len(files)} 个脚本:{C.N}")
    print(f"  {'序号':<6}{'类型':<8}{'大小':<10}文件"); print("  "+"-"*50)
    for i,f in enumerate(files,1):
        print(f"  {i:<6}{os.path.splitext(f)[1].lstrip('.'):<8}{os.path.getsize(f):<10}{os.path.basename(f)}")
    print(f"  {'a':<6}全部")
    sel=input(f"\n{C.C}[?] 序号(逗号分隔, a=全部):{C.N}\n> ").strip().lower()
    from py.core.encryptor import encrypt_file
    targets=files if sel=="a" else []
    if sel!="a":
        for n in sel.replace("，",",").split(","):
            n=n.strip()
            if n.isdigit():
                idx=int(n)-1
                if 0<=idx<len(files): targets.append(files[idx])
    if not targets: print(f"{C.Y}[!] 没选到有效脚本{C.N}"); return
    for f in targets:
        try:
            new,kind=encrypt_file(f); out=f+".xsn"
            open(out,"w",encoding="utf-8").write(new)
            print(f"{C.G}[+] 加密成功 {kind}: {os.path.basename(f)} -> {os.path.basename(out)}{C.N}")
        except Exception as e:
            print(f"{C.Y}[!] 失败 {os.path.basename(f)}: {e}{C.N}")
def do_enterprise_enc():
    import getpass
    path=input(f"{C.C}[?] 输入要加密的文件路径:{C.N}\n> ").strip().strip("'\"")
    if not os.path.isfile(path): print(f"{C.Y}[!] 文件不存在{C.N}"); return
    pw=getpass.getpass(f"{C.C}[?] 设置口令(不显示):{C.N} ")
    if len(pw)<6: print(f"{C.Y}[!] 口令至少 6 位{C.N}"); return
    from py.core.enterprise_crypto import encrypt_file
    out=encrypt_file(path,pw)
    print(f"{C.G}[+] 企业级加密完成: {os.path.basename(out)}{C.N}")
def do_xshen_encrypt():
    import getpass
    path=input(f"{C.C}[?] 输入要加密的文件路径:{C.N}\n> ").strip().strip("'\"")
    if not os.path.isfile(path): print(f"{C.Y}[!] 文件不存在{C.N}"); return
    pw=getpass.getpass(f"{C.C}[?] 设置 XSCipher 密钥(不显示):{C.N} ")
    if len(pw)<4: print(f"{C.Y}[!] 密钥至少 4 位{C.N}"); return
    from py.core.encryptor import xshen_protect
    blob=xshen_protect(open(path,"rb").read(),pw.encode()); out=path+".xsn"
    open(out,"wb").write(blob)
    print(f"{C.G}[+] XSCipher 加密完成: {os.path.basename(out)} ({len(blob)} 字节){C.N}")
    print("     v2: AES-256-GCM + PBKDF2(40万) + 自研异或外层; 菜单1 输入同密钥解密")
def main():
    show_banner()
    while True:
        print(f"""
{C.BOLD}  ====== 菜单 ======{C.N}
  {C.P}1{C.N}) 解密
  {C.P}2{C.N}) 加密 (免密钥·深度混淆壳)
  {C.P}3{C.N}) 企业级加密 (AES-256-GCM·口令)
  {C.P}4{C.N}) XSCipher 加密 (自研v2默认内核)
  {C.P}0{C.N}) 退出
""")
        c=input(f"{C.C}[?] 请选择:{C.N} ").strip()
        if c=="1":do_decrypt()
        elif c=="2":do_encrypt()
        elif c=="3":do_enterprise_enc()
        elif c=="4":do_xshen_encrypt()
        elif c=="0":print(f"{C.P}  再见!{C.N}");break
        else:print(f"{C.Y}[!] 无效选择{C.N}")
if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n{C.Y}[已退出]{C.N}")
