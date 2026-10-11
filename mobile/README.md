# 小神 · 手机端（免 root）工具与权限自查

安卓免 root，主要在 Termux 运行。

## 环境
```bash
pkg update && pkg install -y python
termux-setup-storage     # 访问 /sdcard 需要
# 关 Termux 电池优化；装 Termux:Boot 可开机自启
```

## 权限自查
```bash
python3 mobile/android_perm.py suspicious       # 可疑组合 + 申请>=5类高敏权限的应用
python3 mobile/android_perm.py com.example.app  # 看某应用要了哪些权限
```
高敏覆盖：短信/通讯录/通话记录/相机/麦克风/定位/存储/悬浮窗/安装应用/查询所有应用。

## 常用命令
```bash
pm list packages
dumpsys package <包名>
dumpsys battery
```

## 加固建议
- 相机/麦克风/定位用完即关；
- 非必要不给悬浮窗/安装其它应用/查询所有应用；
- 来源不明 apk 先看权限再装；
- 公网监听务必 --bind 127.0.0.1。

> 免 root 看不到应用运行时行为；深度排查需 root 或 MDM。
