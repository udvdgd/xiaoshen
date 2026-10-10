#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, base64, getpass, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS=600000; SALT_LEN=16; NONCE_LEN=12; KEY_LEN=32

def _derive_key(password,salt):
    return hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,ITERATIONS,KEY_LEN)

def encrypt_bytes(data,password):
    salt=os.urandom(SALT_LEN); nonce=os.urandom(NONCE_LEN)
    key=_derive_key(password,salt)
    return base64.b64encode(salt+nonce+AESGCM(key).encrypt(nonce,data,None)).decode()

def decrypt_bytes(blob,password):
    raw=base64.b64decode(blob)
    salt,nonce,ct=raw[:SALT_LEN],raw[SALT_LEN:SALT_LEN+NONCE_LEN],raw[SALT_LEN+NONCE_LEN:]
    return AESGCM(_derive_key(password,salt)).decrypt(nonce,ct,None)

def encrypt_file(path,password,out_path=None):
    blob=encrypt_bytes(open(path,'rb').read(),password)
    out_path=out_path or (path+".enc")
    open(out_path,'w').write(blob); return out_path

def decrypt_file(enc_path,password,out_path=None):
    data=decrypt_bytes(open(enc_path).read(),password)
    out_path=out_path or enc_path.replace(".enc",".dec")
    open(out_path,'wb').write(data); return out_path
