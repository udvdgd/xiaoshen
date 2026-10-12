# CTF 练习区（教育/竞赛向）

> 仅供 CTF 竞赛、教学、本机靶场练习。不提供可打真实目标的攻击工具。
> 本目录不放“军火库”，只放题型认知与学习路径。

## 题型速览（历年赛题常见）

| 方向 | 比什么 | 练什么基本功 | 安全练习平台 |
|---|---|---|---|
| Pwn（二进制） | 栈/堆溢出、格式化串、UAF 概念与缓解 | 汇编、调试器、内存布局 | picoCTF、ROP Emporium(离线) |
| Web | SQLi、XSS、SSRF、文件包含、反序列化 | HTTP、中间件原理 | picoCTF、PortSwigger Web Academy |
| Crypto | 古典密码、流/分组误用、RSA 弱参数 | 数论、常见密码学坑 | cryptopals(离线) |
| Reverse | 逆向 ELF/APK/PE 找 flag | 反汇编、控制流 | crackmes.one(授权题) |
| Misc | 流量分析、隐写、取证 | Wireshark、binwalk | CTFtime 公开赛 |

## 学习路径
1. picoCTF 入门；2. Web 走 PortSwigger 官方靶场；3. Crypto 刷 cryptopals；4. Pwn 从 ROP Emporium 开始；5. 每题按“原理→缓解→怎么修”复盘。

## 法律边界
只在自己靶机或官方授权环境练习；未授权打真实系统违法。本目录不收录针对生产系统的利用代码。

## 与漏洞库关系
真实 CVE 的防御侧信息见 ../vulns.json、../android_lpe.json；你自己研究的利用细节自行手动管理，本仓库不接收不分发。
