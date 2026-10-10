# 小神代理 · 完整使用教程（含 Telegram 连接）

本地免密双协议代理：**SOCKS5（1080）+ HTTP（1081）**，只转发、不记录/拦截/修改。
SOCKS5 通用性强、域名由代理解析，**Telegram 用它**；HTTP 适合浏览器/命令行。

## 1. 启动
```bash
cd desktop/proxy && chmod +x deploy.sh
./deploy.sh install      # 装依赖+开机自启+启动 (Kali/树莓派/Termux/macOS/Windows)
python3 proxy.py         # 或临时前台运行
```

## 2. 连接地址
| 场景 | 服务器 | 端口 |
|---|---|---|
| 本机 | 127.0.0.1 | SOCKS 1080 / HTTP 1081 |
| 同局域网设备 | 启动画面的局域网 IP | 同上 |

## 3. Telegram（TG）连接
统一填：类型 **SOCKS5**、服务器 `127.0.0.1`（本机）或局域网 IP、端口 `1080`、用户名密码**留空**。
- **Android**：☰→设置→数据和存储→代理设置→添加代理→SOCKS5→填→✓，显示 Connected。
- **iOS**：设置→数据和存储→代理→添加代理→SOCKS5→填→勾选。
- **Desktop(Win/Mac/Linux)**：☰→设置→高级→连接方式→自定义代理→SOCKS5→填，圆点亮。
- **macOS 原生**：设置→Data and Storage→Proxy→Add Proxy→SOCKS5。

## 4. 系统全局代理
- **Windows**：设置→网络→代理→手动，127.0.0.1:1081。
- **macOS**：网络→代理，HTTP/HTTPS 127.0.0.1:1081 或 SOCKS 127.0.0.1:1080。
- **Linux GNOME**：网络代理→手动，SOCKS 127.0.0.1:1080。
- **Android Wi‑Fi**：修改→代理手动→局域网IP:1081（仅HTTP）。
- **iPhone Wi‑Fi**：配置代理→手动→局域网IP:1081。

## 5. 浏览器
- Firefox：网络设置→手动→SOCKS v5 127.0.0.1:1080，勾“代理解析DNS”。
- Chrome/Edge：跟随系统，或 SwitchyOmega/FoxyProxy 建 SOCKS5 127.0.0.1:1080。

## 6. 命令行
```bash
curl -x http://127.0.0.1:1081 https://example.com
curl --socks5-hostname 127.0.0.1:1080 https://example.com
export https_proxy=http://127.0.0.1:1081
```

## 7. 验证
```bash
curl https://ifconfig.me; echo
curl -x http://127.0.0.1:1081 https://ifconfig.me; echo
```

## 8. 排错
| 现象 | 处理 |
|---|---|
| 连不上 | 代理未启动/端口占用/防火墙 |
| 局域网连不上 | 不在同一网络、绑定非0.0.0.0、放行端口 |
| TG 不可用 | 选 SOCKS5、端口1080、无用户名密码 |
| 一会就断 | 设备休眠，用 deploy.sh install |
| Termux 被杀 | 关闭电池优化/Termux:Boot |

## 9. 安全 / 卸载
- 绑 0.0.0.0 免密=局域网开放代理；只本机用请 `--bind 127.0.0.1`；公网务必防火墙白名单。
- 公共 Wi‑Fi 到代理段非加密隧道，端到端安全靠 HTTPS/TG 自身加密。
- 卸载：`./deploy.sh remove`。
