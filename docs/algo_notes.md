# 算法原理笔记

## RC4
KSA + PRGA 两步流密码。

## XXTEA
可变块长分组密码, 特征常数 0x9E3779B9。

## AES
16字节块, S-Box 首字节 0x63 0x7c 0x77 0x7b。

## TEA
8字节块, delta 0x9E3779B9。

## XOR
单字节256种可能, 按关键字评分。

## ELF .so
扫字符串段与常量表, JNI 名 Java_ 暴露入口。

## 企业级
AES-256-GCM 认证加密 + PBKDF2 口令派生, 密钥在脚本外部才是真保护。
