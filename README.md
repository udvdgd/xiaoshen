# 小神算法 · 开源脚本加解密工具包

纯 Python 标准库 + C/Go 加速。MIT 协议，免费开源。

## 快速开始

```bash
python3 run.py
```

## 功能

- 菜单 1：标准算法解密（AES/DES/RC4/TEA/XTEA/XXTEA/ChaCha20/SM4/Blowfish 等）
- 菜单 2：免密钥深度混淆加密（Lua/JS/Python/Shell）
- 菜单 3：企业级 AES-256-GCM 口令加密（PBKDF2 派生）
- 菜单 4：XSCipher 自研外层混淆 + AES-256-GCM 内核

## 手机安全巡检（防御侧）

- `vulndb/`：公开 CVE 防御侧情报库，`query.py` 检索，`PRINCIPLE.md` 提权原理模板（成因分类，无利用代码）。
- `desktop/phone_audit.py`：手机 USB 连电脑后只读读补丁级别，对照漏洞库报告风险；不 root、不利用、不改系统。

```bash
adb devices
python3 desktop/phone_audit.py
```

## 法律边界

仅用于自有/已授权内容保护、CTF、教学与自有设备安全自查。禁止用于破解第三方商业脚本、提权武器化、绕过反作弊/反检测。项目按 AS IS 提供。

## License

[MIT](LICENSE) © xiaoshen contributors
