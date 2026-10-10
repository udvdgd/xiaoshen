# 小神算法 · 桌面版 (Desktop Edition)

Windows / macOS / Linux 命令行加解密，无需管理员权限。

| 实现 | 目录 | 特点 |
|---|---|---|
| Go xshenctl | `go/` | 纯标准库静态二进制，跨平台，单文件/整目录批量/识别/混淆 |
| C xshen-c | `c/` | OpenSSL AES-256-GCM，小而快 |

## 内核
- AES-256-GCM (AEAD) 机密性 + 完整性；
- PBKDF2-HMAC-SHA256 40 万次迭代派生密钥；
- Go 外层叠加自研异或流做形态混淆；错密钥/篡改一律拒绝。

## 构建
```bash
# Go
cd go && go build -o xshenctl ./xshenctl
GOOS=windows go build -o xshenctl.exe ./xshenctl
GOOS=darwin GOARCH=arm64 go build -o xshenctl-mac-arm64 ./xshenctl
# C
cd c && make        # Windows(MinGW): make OS=windows
```

## 使用
```bash
xshenctl enc|dec|obf|info <文件|目录> [密钥]
xshen-c enc|dec <输入> <输出> <密钥>
```

容器: XSD1(Go强) / XSO1(Go混淆) / XSC1(C强) / XSN1·XSN2(手机版)。

> 用于保护自有或授权内容；免密钥自解脚本内部仍含还原材料，属强混淆。
