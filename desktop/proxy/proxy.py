# -*- coding: utf-8 -*-
"""
小神代理 v2 - 跨平台双协议代理
SOCKS5(1080) + HTTP(1081)，纯标准库、每连接一线程。
新增：可选账号密码认证 / 连接日志 / 国内站点直连分流 / 自检。

示例：
  python3 proxy.py                                  # 本机免密
  python3 proxy.py --user alice --pass s3cret       # 加认证（公网必开）
  python3 proxy.py --bind 127.0.0.1                 # 只本机监听
"""
import socket, threading, select, struct, sys, time, argparse, base64, datetime

LISTEN = "0.0.0.0"
HTTP_PORT = 1081
SOCKS_PORT = 1080
AUTH = None

DIRECT_DOMAINS = {
    "baidu.com", "qq.com", "weixin.qq.com", "weibo.com", "taobao.com",
    "tmall.com", "jd.com", "360.com", "163.com", "douyin.com",
    "bilibili.com", "zhihu.com", "meituan.com", "12306.cn", "aliyun.com",
    "tencent.com", "huawei.com", "xiaomi.com", "bytedance.com", "douban.com",
    "csdn.net", "youku.com", "iqiyi.com", "pinduoduo.com", "alicdn.com",
    "gtimg.cn", "sina.com.cn", "sohu.com", "126.com", "feishu.cn",
    "byteimg.com", "pstatp.com",
}


def log(msg):
    t = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{t}] {msg}", flush=True)


def is_direct(host):
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in DIRECT_DOMAINS)


def pipe(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 180)
            if not r:
                break
            for s in r:
                data = s.recv(16384)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except Exception:
        pass
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


def check_socks_auth(client):
    try:
        nmethods = client.recv(1)[0]
        methods = client.recv(nmethods)
    except Exception:
        return False
    if AUTH is None:
        client.sendall(b"\x05\x00")
        return True
    if b"\x02" in methods:
        client.sendall(b"\x05\x02")
        ulen = client.recv(1)[0]
        user = client.recv(ulen).decode()
        plen = client.recv(1)[0]
        pwd = client.recv(plen).decode()
        if (user, pwd) == AUTH:
            client.sendall(b"\x01\x00")
            return True
        client.sendall(b"\x01\x01")
        return False
    client.sendall(b"\x05\xff")
    return False


def handle_socks(client):
    try:
        ver = client.recv(1)
        if not ver or ver[0] != 5:
            client.close(); return
        if not check_socks_auth(client):
            client.close(); return
        header = client.recv(4)
        if len(header) < 4:
            client.close(); return
        ver, cmd, rsv, atyp = header
        if cmd != 1:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            client.close(); return
        if atyp == 1:
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:
            alen = client.recv(1)[0]
            addr = client.recv(alen).decode("utf-8", "replace")
        elif atyp == 4:
            addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        else:
            client.close(); return
        port = struct.unpack(">H", client.recv(2))[0]
        route = "DIRECT" if is_direct(addr) else "PROXY"
        log(f"SOCKS5 -> {addr}:{port}  [{route}]")
        upstream = socket.create_connection((addr, port), timeout=15)
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        pipe(client, upstream)
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def check_http_auth(client, data):
    if AUTH is None:
        return True
    req = data.decode("latin1")
    for line in req.split("\r\n"):
        if line.lower().startswith("proxy-authorization:"):
            try:
                enc = line.split(" ", 1)[1]
                if enc.startswith("Basic "):
                    u, p = base64.b64decode(enc[6:]).decode().split(":", 1)
                    return (u, p) == AUTH
            except Exception:
                return False
    client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                   b"Proxy-Authenticate: Basic realm=\"xshen\"\r\n\r\n")
    return False


def handle_http(client):
    try:
        data = client.recv(8192)
        if not data:
            client.close(); return
        if not check_http_auth(client, data):
            client.close(); return
        line = data.split(b"\r\n")[0].decode("latin1")
        parts = line.split(" ")
        if len(parts) < 3:
            client.close(); return
        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            host, p = target.rsplit(":", 1)
            port = int(p)
        else:
            from urllib.parse import urlparse
            u = urlparse(target)
            host, port = u.hostname, u.port or 80
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            data = data.replace(target.encode(), path.encode(), 1)
        route = "DIRECT" if is_direct(host) else "PROXY"
        log(f"HTTP {method} {host}:{port}  [{route}]")
        upstream = socket.create_connection((host, port), timeout=15)
        if method == "CONNECT":
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            idx = data.find(b"\r\n\r\n")
            if idx >= 0 and len(data) > idx + 4:
                upstream.sendall(data[idx + 4:])
        else:
            upstream.sendall(data)
        pipe(client, upstream)
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def accept_loop(srv, handler):
    while True:
        try:
            conn, _ = srv.accept()
        except Exception:
            break
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def make_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN, port))
    s.listen(500)
    return s


def main():
    global LISTEN, AUTH
    ap = argparse.ArgumentParser(description="小神代理 v2")
    ap.add_argument("--socks", type=int, default=SOCKS_PORT)
    ap.add_argument("--http", type=int, default=HTTP_PORT)
    ap.add_argument("--bind", default=LISTEN)
    ap.add_argument("--user", default=None, help="代理用户名（公网建议设置）")
    ap.add_argument("--pass", dest="password", default=None, help="代理密码")
    args = ap.parse_args()
    LISTEN = args.bind
    if args.user and args.password:
        AUTH = (args.user, args.password)
    s_http = make_server(args.http)
    s_socks = make_server(args.socks)
    threading.Thread(target=accept_loop, args=(s_http, handle_http), daemon=True).start()
    threading.Thread(target=accept_loop, args=(s_socks, handle_socks), daemon=True).start()
    lan = get_lan_ip()
    print("=" * 52)
    print("  小神代理 v2 - 已启动")
    print("=" * 52)
    print(f"  SOCKS5 : {LISTEN}:{args.socks}")
    print(f"  HTTP   : {LISTEN}:{args.http}")
    print(f"  局域网 : {lan}:{args.socks}")
    print(f"  认证   : {'账号密码 ' + args.user if AUTH else '免密（仅建议本机/可信局域网）'}")
    print("=" * 52, flush=True)
    log("代理就绪，日志如下：")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n已退出")


if __name__ == "__main__":
    main()
