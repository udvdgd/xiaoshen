# 小神漏洞知识库（vulndb）

收录著名公开 CVE 的**防御侧**信息：影响版本、风险点、如何检测、修复方案、官方参考。
**只做知识整理与检测/修复指引，不含任何可直接利用的攻击代码或 PoC payload。**

## 使用
```bash
cd vulndb
python3 query.py list                # 列出全部
python3 query.py search log4j        # 按关键字搜
python3 query.py show CVE-2021-44228 # 看某条详情
```

## 收录方向
- Web 中间件：Struts2、Spring、Apache httpd、ActiveMQ、PHP-FPM
- 边界设备：F5 BIG-IP、Citrix ADC、FortiGate
- 协作套件：Confluence、Exchange、MOVEit
- 操作系统/协议：SMBv1/v3、RDP、Netlogon、OpenSSL、Office/MSDT
- 已 EOL 组件：Flash

## 字段
id/name/product/affected/severity/summary/detect/remediate/ref(NVD)。

## 边界
用于自查、巡检、教育；禁止未授权攻击。数据以厂商通告为准。
