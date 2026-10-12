# 小神代理 v2（免费开源 · 本地双协议）

纯本地转发代理：**SOCKS5 (默认1080) + HTTP (默认1081)**，纯 Python 标准库，
每连接独立线程。**免费、无登录、无广告、无遥测**，仅做转发，不含任何拦截或攻击功能。

## v2 新特性
- **可选账号密码认证**：`--user/--pass`，公网/不可信网络必开，防白嫖；
- **连接日志**：实时打印每条连接目标与 `DIRECT`/`PROXY` 走向；
- **国内站点自动直连分流**：常用国内域名直连，其余走代理出口；
- **绑定控制**：`--bind 127.0.0.1` 仅本机，`--bind 0.0.0.0` 开放局域网。

## 一键部署 / 启动

```bash
chmod +x deploy.sh
./deploy.sh install      # 自动识别系统, 装依赖 + 开机自启 + 立即启动
./deploy.sh start        # 仅前台启动
./deploy.sh remove       # 卸载服务
```

支持环境：

| 系统 | 方式 |
|---|---|
| Kali / Debian / Ubuntu / Raspberry Pi OS | apt + systemd |
| Arch / Manjaro | pacman + systemd |
| Fedora / RHEL / CentOS / Rocky / Alma | dnf + systemd |
| Alpine | apk + 前台 |
| Android (Termux，免root) | pkg + Termux:Boot |
| macOS | launchd (LaunchAgent) |
| Windows | 双击 `start.bat` |

## 直接运行
```bash
python3 proxy.py                                  # 本机免密
python3 proxy.py --bind 127.0.0.1                 # 只本机连（最安全）
python3 proxy.py --user myname --pass '强密码'    # 加认证（公网推荐）
python3 proxy.py --socks 1080 --http 1081 --bind 0.0.0.0
```

## 客户端连接
- 本机：`127.0.0.1:1080`(SOCKS5) / `127.0.0.1:1081`(HTTP)
- 局域网设备：`启动时显示的局域网IP:1080`
- Telegram：App 内加 SOCKS5 代理，填上面地址端口；若开了认证则填 `--user/--pass`。

详细图文（含 Telegram / 浏览器 / 系统全局 / 命令行 / 排错）见 [GUIDE.md](GUIDE.md)。

> 安全提示：只本机用请 `--bind 127.0.0.1`；公网服务器必须同时加 `--user/--pass` 和防火墙白名单，避免成为开放代理被滥用。
