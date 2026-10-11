# 小神漏洞知识库（vulndb）

用于**安全演习/自查巡检**的公开 CVE 防御侧知识库：影响版本、风险点、检测、修复、官方参考。**不含攻击代码/PoC。**

## 快速开始
```bash
python3 query.py list                 # 列出全部
python3 query.py search log4j
python3 query.py show CVE-2021-44228
```

## 扩充到几千上万条（真实数据）
精选种子 `vulns.json` 内置 21 条；用官方公开数据导入：
```bash
# 1) 从 https://nvd.nist.gov/vuln/data-feeds 下载 nvdcve-1.1-YYYY.json
python3 import_feed.py nvd nvdcve-1.1-2024.json
python3 import_feed.py generic my_list.json
```
生成 `vulns_full.json` 后 query.py 自动优先读取（几千~上万条）。

## 文件
| 文件 | 说明 |
|---|---|
| vulns.json | 精选种子（内置 21 条） |
| vulns_full.json | 导入官方 Feed 后生成（不入库） |
| import_feed.py | NVD/通用 JSON 导入器 |
| query.py | list/search/show |

## 边界
用于自有环境安全演习/自查/教育；禁止未授权攻击；以厂商公告为准。
