# -*- coding: utf-8 -*-
"""小神代理 - 纯本地免密版 (跨平台). SOCKS5(1080)+HTTP(1081), 每连接独立线程。"""
import socket, threading, select, struct, sys, time, argparse

LISTEN = "0.0.0.0"
HTTP_PORT = 1081
SOCKS_PORT = 1080

DIRECT_DOMAINS = {
    "baidu.com", "qq.com", "weixin.qq.com", "weibo.com", "taobao.com", "tmall.com",
    "jd.com", "360.com", "163.com", "douyin.com", "bilibili.com", "zhihu.com",
    "meituan.com", "12306.cn", "aliyun.com", "tencent.com", "huawei.com", "xiaomi.com",
    "bytedance.com", "douban.com", "csdn.net", "youku.com", "iqiyi.com",
    "pinduoduo.com", "alicdn.com", "gtimg.cn", "sina.com.cn", "sohu.com", "126.com",
    "feishu.cn", "byteimg.com", "pstatp.com",
}


def is_cn(host):
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in DIRECT_DOMAINS)


def pipe(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 120)
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


def handle_socks(client):
    try:
        ver = client.recv(1)
        if not ver or ver[0] != 5:
            client.close(); return
        nmethods = client.recv(1)[0]
        client.recv(nmethods)
        client.sendall(b"\x05\x00")
        header = client.recv(4)
        if len(header) < 4:
            client.close(); return
        ver, cmd, rsv, atyp = header
        if cmd != 1:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6); client.close(); return
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
        upstream = socket.create_connection((addr, port), timeout=15)
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        pipe(client, upstream)
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def handle_http(client):
    try:
        data = client.recv(8192)
        if not data:
            client.close(); return
        line = data.split(b"\r\n")[0].decode("latin1")
        parts = line.split(" ")
        if len(parts) < 3:
            client.close(); return
        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            host, p = target.rsplit(":", 1); port = int(p)
        else:
            from urllib.parse import urlparse
            u = urlparse(target)
            host, port = u.hostname, u.port or 80
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            data = data.replace(target.encode(), path.encode(), 1)
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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"


def make_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN, port)); s.listen(500); return s


def main():
    global LISTEN
    ap = argparse.ArgumentParser(description="小神代理")
    ap.add_argument("--socks", type=int, default=SOCKS_PORT)
    ap.add_argument("--http", type=int, default=HTTP_PORT)
    ap.add_argument("--bind", default=LISTEN)
    args = ap.parse_args()
    LISTEN = args.bind
    s_http = make_server(args.http); s_socks = make_server(args.socks)
    threading.Thread(target=accept_loop, args=(s_http, handle_http), daemon=True).start()
    threading.Thread(target=accept_loop, args=(s_socks, handle_socks), daemon=True).start()
    lan = get_lan_ip()
    print("=" * 50)
    print("  小神代理 - 已启动"); print("=" * 50)
    print(f"  SOCKS5 : {LISTEN}:{args.socks}"); print(f"  HTTP   : {LISTEN}:{args.http}")
    print(f"  局域网 : {lan}:{args.socks}"); print("  认证   : 免密"); print("=" * 50, flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n已退出")


if __name__ == "__main__":
    main()
