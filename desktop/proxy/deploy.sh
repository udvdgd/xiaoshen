#!/usr/bin/env bash
# 小神代理 一键部署: ./deploy.sh install|start|remove
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
SERVICE_NAME="xshen-proxy"
PYBIN="$(command -v python3 || command -v python || true)"

detect_os() {
  case "$(uname -s)" in
    Linux*)
      if [ -n "${PREFIX:-}" ] && echo "$PREFIX" | grep -q com.termux; then echo termux
      elif [ -f /etc/os-release ]; then . /etc/os-release; echo "linux:${ID:-unknown}"
      else echo "linux:unknown"; fi ;;
    Darwin*) echo macos ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) echo unknown ;;
  esac
}
need_python() { [ -n "$PYBIN" ] || { echo "[!] 未找到 python3" >&2; exit 1; }; }

install_linux_systemd() {
  echo "[*] systemd 注册服务"; [ -z "$PYBIN" ] && PYBIN=python3
  sudo tee /etc/systemd/system/${SERVICE_NAME}.service >/dev/null <<EOF
[Unit]
Description=Xshen local proxy
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$PYBIN $HERE/proxy.py
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload; sudo systemctl enable --now ${SERVICE_NAME}
  echo "[+] 已启动: systemctl status ${SERVICE_NAME}"
}
install_termux() {
  echo "[*] Termux (免root)"; command -v pkg >/dev/null && pkg install -y python >/dev/null
  mkdir -p "$HOME/.termux/boot"
  cat > "$HOME/.termux/boot/xshen-proxy.sh" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
exec python $HERE/proxy.py
EOF
  chmod +x "$HOME/.termux/boot/xshen-proxy.sh"
  echo "[+] 已写入 Termux:Boot"
}
install_macos() {
  echo "[*] macOS launchd"
  PLIST="$HOME/Library/LaunchAgents/com.xshen.proxy.plist"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.xshen.proxy</string>
<key>ProgramArguments</key><array><string>$PYBIN</string><string>$HERE/proxy.py</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
EOF
  launchctl load "$PLIST" 2>/dev/null || true; echo "[+] 已加载"
}
ensure_deps() {
  case "$1" in
    linux:kali|linux:debian|linux:ubuntu|linux:raspbian|linux:linuxmint|linux:pop)
      command -v python3 >/dev/null || { sudo apt-get update; sudo apt-get install -y python3; } ;;
    linux:arch|linux:manjaro)
      command -v python3 >/dev/null || sudo pacman -Sy --noconfirm python ;;
    linux:fedora|linux:centos|linux:rhel|linux:rocky|linux:alma)
      command -v python3 >/dev/null || sudo dnf install -y python3 ;;
    linux:alpine)
      command -v python3 >/dev/null || sudo apk add --no-cache python3 ;;
  esac
}
remove_svc() {
  case "$(detect_os)" in
    termux) rm -f "$HOME/.termux/boot/xshen-proxy.sh" ;;
    macos) launchctl unload "$HOME/Library/LaunchAgents/com.xshen.proxy.plist" 2>/dev/null; rm -f "$HOME/Library/LaunchAgents/com.xshen.proxy.plist" ;;
    *) sudo systemctl disable --now ${SERVICE_NAME} 2>/dev/null || true; sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service; sudo systemctl daemon-reload ;;
  esac
  echo "[+] 已卸载"
}
ACTION="${1:-start}"; OS="$(detect_os)"
case "$ACTION" in
  install)
    ensure_deps "$OS"
    case "$OS" in
      termux) install_termux ;;
      macos) need_python; install_macos ;;
      windows) echo "Windows 请双击 start.bat" ;;
      linux:*) need_python; if command -v systemctl >/dev/null; then install_linux_systemd; else exec "$PYBIN" "$HERE/proxy.py"; fi ;;
      *) exec "$PYBIN" "$HERE/proxy.py" ;;
    esac ;;
  start) need_python; exec "$PYBIN" "$HERE/proxy.py" ;;
  remove) remove_svc ;;
  *) echo "用法: $0 install|start|remove" ;;
esac
