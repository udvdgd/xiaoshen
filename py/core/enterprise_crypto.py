#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================
小神 · 企业级认证加密模块 (真正的行业标准)
================================================================
密钥派生: PBKDF2-HMAC-SHA256, 随机 16 字节 salt, 600000 次迭代
加密    : AES-256-GCM (机密性 + 完整性 + 防篡改)
编码    : base64(salt|nonce|ciphertext+tag)
密钥只存在于用户口令中, 无口令不可破解。
================================================================
"""
import os
import base64
import getpass
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 600_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, KEY_LEN)


def encrypt_bytes(data: bytes, password: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return base64.b64encode(salt + nonce + ct).decode("ascii")


def decrypt_bytes(blob: str, password: str) -> bytes:
    raw = base64.b64decode(blob)
    salt, nonce, ct = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN+NONCE_LEN], raw[SALT_LEN+NONCE_LEN:]
    key = _derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


def encrypt_file(path: str, password: str, out_path: str | None = None) -> str:
    data = open(path, "rb").read()
    blob = encrypt_bytes(data, password)
    out_path = out_path or (path + ".enc")
    with open(out_path, "w", encoding="ascii") as fp:
        fp.write(blob)
    return out_path


def decrypt_file(enc_path: str, password: str, out_path: str | None = None) -> str:
    blob = open(enc_path, "r", encoding="ascii").read()
    data = decrypt_bytes(blob, password)
    out_path = out_path or enc_path.replace(".enc", ".dec")
    with open(out_path, "wb") as fp:
        fp.write(data)
    return out_path


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: enterprise_crypto.py enc|dec 文件")
        sys.exit(1)
    action, target = sys.argv[1], sys.argv[2]
    pw = getpass.getpass("口令: ")
    if action == "enc":
        print("已输出:", encrypt_file(target, pw))
    else:
        print("已输出:", decrypt_file(target, pw))
