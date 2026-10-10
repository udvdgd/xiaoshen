# 小神代理 (本地免密双协议)

纯本地转发: SOCKS5(1080)+HTTP(1081), 免登录/免配置, 每连接独立线程。

## 一键部署
```bash
chmod +x deploy.sh
./deploy.sh install   # 装依赖+开机自启+启动
./deploy.sh start
./deploy.sh remove
```

| 系统 | 方式 |
|---|---|
| Kali/Debian/Ubuntu/树莓派OS | apt+systemd |
| Arch/Manjaro | pacman+systemd |
| Fedora/RHEL/Rocky/Alma | dnf+systemd |
| Alpine | apk+前台 |
| Android Termux(免root) | pkg+Termux:Boot |
| macOS | launchd |
| Windows | start.bat |

直接运行: `python3 proxy.py [--socks 1080 --http 1081 --bind 0.0.0.0]`

> 绑定 0.0.0.0 免密会成为局域网开放代理; 公网请 --bind 127.0.0.1。
