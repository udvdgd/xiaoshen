# 小神算法 · xiaoshen

跨平台**脚本加解密 + 防御安全**开源工具箱。手机版（Python，免 root）、桌面版（Go / C，Windows·macOS·Linux）、只读安全巡检与本地代理。**MIT，免费开源。**

```bash
python3 run.py
```

## 一、包含模块

| 模块 | 语言 | 位置 | 说明 |
|---|---|---|---|
| 手机版 | Python | `run.py`、`py/` | 交互菜单，标准算法解密 + 多种加密 |
| 桌面 CLI | Go | `desktop/go/xshenctl` | 静态单文件，批量/识别/混淆 |
| 桌面 CLI | C | `desktop/c/xshen-c.c` | OpenSSL AES-256-GCM |
| 安全巡检 | Go | `desktop/go/xsec` | 只读防御巡检 |
| 本地代理 | Python | `desktop/proxy` | SOCKS5+HTTP，一键部署 |
| C 加速 | C | `c/` | XOR/RC4 爆破、ELF 字符串 |

## 二、手机版 `python3 run.py`

1. 解密（填目录自动识别）；2. 免密钥深度混淆加密（Lua/JS/Python/Shell）；3. 企业级 AES-256-GCM 口令加密；4. XSCipher 加密（默认 v2）→ `.xsn`。

算法：AES、DES/3DES、RC4、Blowfish、TEA/XTEA/XXTEA、ChaCha20、SM4、XSCipher v1/v2、Base64/32/16、zlib、gzip、单字节 XOR 爆破、自研异或流。

## 三、桌面版

```bash
cd desktop/go && go build -o xshenctl ./xshenctl
GOOS=windows go build -o xshenctl.exe ./xshenctl
xshenctl enc|dec|obf|info <文件|目录> [密钥]
cd desktop/c && make && xshen-c enc|dec <输入> <输出> <密钥>
```

容器：`XSN1/XSN2`（手机 v1/v2）、`XSD1`（Go强）、`XSO1`（Go混淆）、`XSC1`（C强）。内核 AES-256-GCM(AEAD)+PBKDF2 40万迭代，错密钥/篡改一律拒绝。

## 四、安全巡检 xsec（只读）

```bash
cd desktop/go && go build -o xsec ./xsec
xsec list ; xsec run <模块|all> [目标]
```

模块：`sys.info` `audit.env` `net.interfaces` `net.tls` `web.headers` `fs.secrets` `hardening.tips`。无漏洞利用/爆破/提权。

## 五、本地代理

```bash
cd desktop/proxy && ./deploy.sh install   # Kali/树莓派/Termux/macOS/Windows
python3 proxy.py                          # SOCKS5 1080 / HTTP 1081
```

公网请 `--bind 127.0.0.1`，避免开放代理。详细教程见 `desktop/proxy/GUIDE.md`。

## 六、目录结构

```
run.py  py/(core,plugins)  c/  desktop/(go/xshenctl,go/xsec,c,proxy)  samples/  docs/  LICENSE
```

## 七、安全说明

- “免密钥自解 + 数学上不可逆”原理矛盾：自解脚本必含还原材料，属强混淆；
- 要真正隔离请用带口令/密钥容器（菜单3/4、XSD1、XSC1）；
- 企业级路线是密钥管理(KMS/HSM)+标准 AEAD，而非自研“无敌算法”。

## 八、法律边界

用于保护自有或授权内容、CTF/教学、标准算法学习。禁止破解第三方付费/商业脚本或非法用途，后果自负，项目按 AS IS 提供。

## License

[MIT](LICENSE) © xiaoshen contributors
