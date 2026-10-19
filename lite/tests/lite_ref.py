# -*- coding: utf-8 -*-
"""Lite module reference implementation (executable definition of the byte format).

The PL/SQL package PKG_SFC must produce byte-identical results. The blob layout
and the password layout are the same as the full edition (tools/refimpl/ocsecure_ref.py);
only the key derivation is specific to the lite edition:

    root key (32 random bytes, stored wrapped in SFC_KEY)
      enc_key = HMAC-SHA256(key=root, msg='OCS-LITE/ENC/v1')
      mac_key = HMAC-SHA256(key=root, msg='OCS-LITE/MAC/v1')
    seal (32 random bytes, kept in package SFC_SEAL)
      seal_enc = HMAC-SHA256(key=seal, msg='OCS-LITE/SEAL-ENC/v1')
      seal_mac = HMAC-SHA256(key=seal, msg='OCS-LITE/SEAL-MAC/v1')
    wrapped root = blob(plain=root, key_id=0, seal_enc, seal_mac)
"""

import hashlib
import hmac
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), 'tools', 'refimpl'))
import ocsecure_ref as ref  # noqa: E402

LBL_ENC = b'OCS-LITE/ENC/v1'
LBL_MAC = b'OCS-LITE/MAC/v1'
LBL_SEAL_ENC = b'OCS-LITE/SEAL-ENC/v1'
LBL_SEAL_MAC = b'OCS-LITE/SEAL-MAC/v1'


def derive(root, label):
    return hmac.new(root, label, hashlib.sha256).digest()


def pack_with_root(root, key_id, plain, iv=None):
    return ref.encrypt(plain, key_id, derive(root, LBL_ENC), derive(root, LBL_MAC), iv)


def unpack_with_root(root, blob):
    return ref.decrypt(blob, derive(root, LBL_ENC), derive(root, LBL_MAC))


def wrap_root(root, seal, iv=None):
    return ref.encrypt_bytes(root, 0, derive(seal, LBL_SEAL_ENC), derive(seal, LBL_SEAL_MAC), iv)


def unwrap_root(blob, seal):
    return ref.decrypt_bytes(blob, derive(seal, LBL_SEAL_ENC), derive(seal, LBL_SEAL_MAC))


def pwd_hash(password, salt, iterations):
    return ref.password_hash(password, salt, iterations)


# --- fixed vectors (the same values are embedded in sql/50_selftest.sql) ---------

KAT_ROOT = bytes(range(32))
KAT_SEAL = bytes(range(32, 64))
KAT_KEY_ID = 7
KAT_IV = bytes([0xA0]) * 16
KAT_IV2 = bytes([0xB0]) * 16
KAT_PLAIN_RRN = '9001011234567'
KAT_PLAIN_KO = u'한글테스트'   # Korean text, 5 chars
KAT_PWD = '!Pass-Word1'
KAT_PWD_SALT = bytes([0x11]) * 16
KAT_PWD_ITER = 3


def vectors():
    pwd = pwd_hash(KAT_PWD, KAT_PWD_SALT, KAT_PWD_ITER)
    pwd = pwd if isinstance(pwd, bytes) else bytes(pwd)
    return {
        'ROOT': KAT_ROOT.hex().upper(),
        'SEAL': KAT_SEAL.hex().upper(),
        'DERIVE_ENC': derive(KAT_ROOT, LBL_ENC).hex().upper(),
        'PACK_RRN': pack_with_root(KAT_ROOT, KAT_KEY_ID, KAT_PLAIN_RRN, KAT_IV).hex().upper(),
        'PACK_KO': pack_with_root(KAT_ROOT, KAT_KEY_ID, KAT_PLAIN_KO, KAT_IV).hex().upper(),
        'WRAP_ROOT': wrap_root(KAT_ROOT, KAT_SEAL, KAT_IV2).hex().upper(),
        'PWD': pwd.hex().upper(),
    }


if __name__ == '__main__':
    for k, v in vectors().items():
        print('%-10s %d  %s' % (k, len(v), v))
