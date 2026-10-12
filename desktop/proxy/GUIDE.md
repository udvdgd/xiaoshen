# 小神代理 · 完整使用教程（含 Telegram 连接）

本地双协议代理：**SOCKS5（默认 1080）+ HTTP（默认 1081）**。
它只做一件事——把你的流量转发出去，不记录、不拦截、不修改内容。

- **SOCKS5**：通用性最强，支持任意 TCP、域名由代理端解析，**Telegram 用它**；
- **HTTP**：适合浏览器、命令行（curl/apt 等）走 http/https。

---

## v2 更新（本次优化）

- **可选账号密码认证**：公网/不可信网络必开，防止被陌生人白嫖；
  ```bash
  python3 proxy.py --user yourname --pass '你的强密码'
  ```
  开了认证后，所有设备（含 TG、浏览器）都要填这组账号密码。
- **连接日志**：每条连接实时打印目标与走的是 `DIRECT`（国内站点直连）还是 `PROXY`；
- **国内站点直连分流**：内置常用国内域名走直连，其余走代理出口，自动生效；
- **绑定控制**：`--bind 127.0.0.1` 只允许本机连（最安全），`--bind 0.0.0.0` 才允许局域网其他设备连。

> 安全原则：只本机用 → `--bind 127.0.0.1`；给手机/同 Wi‑Fi 用 → `--bind 0.0.0.0`；公网 VPS → 必须同时 `--user/--pass` 加防火墙白名单。

---

## 1. 启动代理

### 一键部署（推荐）
```bash
cd desktop/proxy
chmod +x deploy.sh
./deploy.sh install      # 装依赖 + 开机自启 + 立即启动
```
支持 Kali / Debian / Ubuntu / 树莓派 OS / Arch / Fedora·RHEL / Alpine / Android Termux（免 root）/ macOS / Windows。

### 临时前台运行
```bash
python3 proxy.py
# 自定义端口 / 绑定 / 认证
python3 proxy.py --socks 1080 --http 1081 --bind 0.0.0.0 --user name --pass 'pw'
```

### Windows
双击 `start.bat`（需先装 Python，勾选 Add to PATH）。

---

## 2. 拿到连接地址

| 场景 | 服务器地址 | 端口 |
|---|---|---|
| 代理所在本机 | `127.0.0.1` | SOCKS `1080` / HTTP `1081` |
| 同一 Wi‑Fi/局域网其他设备 | 启动画面的“局域网 IP”，如 `192.168.1.20` | 同上 |

---

## 3. Telegram 连接教程（TG）

信息统一填：类型 **SOCKS5**；服务器本机填 `127.0.0.1`、其他设备填局域网 IP；端口 `1080`；用户名/密码默认留空，若启动加了 `--user/--pass` 就填那组。

- **Android**：☰ → 设置 → 数据和存储 → 代理设置 → 添加代理 → SOCKS5 → 填服务器端口 → 保存并选中，显示 Connected。
- **iOS**：设置 → 数据和存储 → 代理 → 添加代理 → SOCKS5 → 填地址端口 → 勾选。
- **Desktop**：☰ → 设置 → 高级 → 连接方式 → 自定义代理 → SOCKS5 `127.0.0.1:1080` → 保存。

> 可同时加多个代理勾选；走局域网另一台设备时那台必须保持运行、不休眠。

---

## 4. 系统全局代理

- **Windows**：设置→网络和 Internet→代理→手动，地址 `127.0.0.1` 端口 `1081`。
- **macOS**：系统设置→网络→网卡→代理，HTTP/HTTPS `127.0.0.1:1081`，或 SOCKS `127.0.0.1:1080`。
- **Linux(GNOME)**：设置→网络→网络代理→手动，SOCKS `127.0.0.1:1080`。
- **Android**：当前 Wi‑Fi→修改→代理手动→主机局域网 IP、端口 `1081`（系统 Wi‑Fi 只支持 HTTP）。
- **iPhone**：Wi‑Fi→当前网络→配置代理手动，服务器局域网 IP、端口 `1081`。

---

## 5. 浏览器

- **Firefox**：设置→网络设置→手动→SOCKS `127.0.0.1:1080`，选 v5，勾“代理 DNS”。
- **Chrome/Edge**：跟随系统代理；或装 SwitchyOmega 建 SOCKS5 `127.0.0.1:1080`。

---

## 6. 命令行

```bash
curl -x http://127.0.0.1:1081 https://example.com
curl --socks5-hostname 127.0.0.1:1080 https://example.com
export http_proxy=http://127.0.0.1:1081
export https_proxy=http://127.0.0.1:1081
```

---

## 7. 验证是否生效

```bash
curl https://ifconfig.me ;
curl -x http://127.0.0.1:1081 https://ifconfig.me ;
```
两个出口 IP 不同即生效。

---

## 8. 排错

| 现象 | 处理 |
|---|---|
| 连不上 | 代理没启动 / 端口被占（换 --socks）/ 防火墙放行 |
| 局域网连不上 | 同网段、绑 0.0.0.0、防火墙放行 |
| TG 不可用 | 类型选 SOCKS5、端口 1080、账密与启动一致 |
| 能连打不开网页 | http 用 1081、socks 用 1080，别填反 |
| 一会儿就断 | 设备休眠/进程被杀，用 deploy.sh install 做后台服务 |

---

## 9. 安全与卸载

- 只本机用请 `--bind 127.0.0.1`；公网 VPS 必须加 `--user/--pass` + 防火墙白名单，否则会被扫描器滥用。
- 本代理不提供加密隧道，公共 Wi‑Fi 下到代理这一段仍明文，端到端加密依赖 HTTPS/Telegram 自身。

卸载：`./deploy.sh remove`
