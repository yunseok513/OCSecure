# -*- coding: utf-8 -*-
"""OCSecure 암호문 포맷 참조 구현.

PL/SQL 구현(sql/02_packages)과 바이트 단위로 동일한 결과를 내는 것이 이 모듈의
목적입니다. 세 가지 용도로 사용합니다.

  1. 포맷 규격의 실행 가능한 정의. 문서의 서술과 구현이 어긋나는 것을 막습니다.
  2. 고정 시험 벡터 생성. PL/SQL 자체 시험이 이 벡터와 대조하여 동작을 검증합니다.
  3. 자바 등 응용 계층이 같은 포맷을 읽고 써야 할 때의 대조 기준.

모든 문자열은 UTF-8로 인코딩합니다. 데이터베이스 문자집합에 의존하지 않기 위한
결정이며, PL/SQL 쪽에서도 UTL_I18N을 사용하여 동일하게 처리합니다.
"""

import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- 포맷 상수 -------------------------------------------------------------

FMT_VERSION = 0x01                  # 암호문 포맷 버전
ALG_AES256_CBC_HMAC_SHA256 = 0x01   # 임시 구현체(오라클 내장)용 알고리즘 식별자
# 0x10~ 대역은 검증필 모듈 도입 시 국산 블록암호에 배정한다. (예: 0x10 ARIA-256)

IV_LEN = 16
TAG_LEN = 32
HDR_LEN = 4                         # ver(1) + alg(1) + key_id(2)

KDF_VERSION = 0x01
KDF_PBKDF2_HMAC_SHA256 = 0x01
PWD_SALT_LEN = 16
PWD_DK_LEN = 32


class CryptoFormatError(Exception):
    pass


# --- 정규화 ----------------------------------------------------------------

def normalize(plain, mode):
    """블라인드 인덱스 계산 전 평문 정규화. 도메인 정책이 모드를 지정한다."""
    if plain is None:
        return None
    if mode == 'NONE':
        return plain
    # 아래 세 규칙은 오라클 쪽 구현과 의미가 정확히 같아야 한다.
    # TRIM 은 공백(U+0020)만 제거하고, DIGITS 는 ASCII 숫자만 남긴다.
    if mode == 'TRIM':
        return plain.strip(' ')
    if mode == 'UPPER_TRIM':
        return plain.strip(' ').upper()
    if mode == 'DIGITS':          # 주민등록번호, 계좌번호 등에서 구분자 제거
        return ''.join(ch for ch in plain if ch in '0123456789')
    raise CryptoFormatError('unknown normalize mode: %s' % mode)


# --- 양방향 암복호화 -------------------------------------------------------

def _pkcs5_pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _pkcs5_unpad(data, block=16):
    if not data or len(data) % block != 0:
        raise CryptoFormatError('bad padded length')
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise CryptoFormatError('bad PKCS#5 padding')
    return data[:-n]


def _header(key_id, alg_id=ALG_AES256_CBC_HMAC_SHA256):
    if not 0 <= key_id <= 0xFFFF:
        raise CryptoFormatError('key_id out of range: %d' % key_id)
    return bytes([FMT_VERSION, alg_id, (key_id >> 8) & 0xFF, key_id & 0xFF])


def encrypt_bytes(plain_bytes, key_id, enc_key, mac_key, iv=None):
    """바이트열 -> 암호문 블롭.

    블롭 = ver(1) | alg(1) | key_id(2) | iv(16) | ciphertext(n) | tag(32)
    태그는 앞 전체(ver..ciphertext)에 대한 HMAC-SHA256이다. 곧 Encrypt-then-MAC.
    문자열이 아닌 키 자료를 감쌀 때도 같은 포맷을 쓴다.
    """
    if plain_bytes is None:
        return None
    if len(enc_key) != 32 or len(mac_key) != 32:
        raise CryptoFormatError('enc_key/mac_key must be 32 bytes')
    iv = iv if iv is not None else os.urandom(IV_LEN)
    if len(iv) != IV_LEN:
        raise CryptoFormatError('iv must be 16 bytes')

    body = _pkcs5_pad(plain_bytes)
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(body) + encryptor.finalize()

    signed = _header(key_id) + iv + ct
    tag = hmac.new(mac_key, signed, hashlib.sha256).digest()
    return signed + tag


def encrypt(plain, key_id, enc_key, mac_key, iv=None):
    """평문 문자열 -> 암호문 블롭. 문자열은 항상 UTF-8로 인코딩한다."""
    if plain is None:
        return None
    return encrypt_bytes(plain.encode('utf-8'), key_id, enc_key, mac_key, iv)


def parse_header(blob):
    """복호화 전에 키를 찾기 위해 헤더만 읽는다. 무결성 검증 전이므로 신뢰하지 않는다."""
    if blob is None:
        return None
    if len(blob) < HDR_LEN + IV_LEN + 16 + TAG_LEN:
        raise CryptoFormatError('blob too short: %d' % len(blob))
    ver, alg = blob[0], blob[1]
    if ver != FMT_VERSION:
        raise CryptoFormatError('unsupported format version: %d' % ver)
    key_id = (blob[2] << 8) | blob[3]
    return {'version': ver, 'alg_id': alg, 'key_id': key_id}


def decrypt_bytes(blob, enc_key, mac_key):
    """암호문 블롭 -> 바이트열. 태그 검증에 실패하면 복호화를 수행하지 않는다."""
    if blob is None:
        return None
    parse_header(blob)
    signed, tag = blob[:-TAG_LEN], blob[-TAG_LEN:]
    calc = hmac.new(mac_key, signed, hashlib.sha256).digest()
    if not hmac.compare_digest(calc, tag):
        raise CryptoFormatError('integrity check failed')
    iv = signed[HDR_LEN:HDR_LEN + IV_LEN]
    ct = signed[HDR_LEN + IV_LEN:]
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    return _pkcs5_unpad(decryptor.update(ct) + decryptor.finalize())


def decrypt(blob, enc_key, mac_key):
    """암호문 블롭 -> 평문 문자열."""
    out = decrypt_bytes(blob, enc_key, mac_key)
    return None if out is None else out.decode('utf-8')


# --- 키 래핑 (KEK 로 DEK 를 감싼다) ----------------------------------------

KEK_ENC_LABEL = b'OCSECURE/KEK/ENC/v1'
KEK_MAC_LABEL = b'OCSECURE/KEK/MAC/v1'


def kek_subkeys(kek):
    """마스터 키에서 래핑용 암호화 키와 무결성 키를 유도한다.

    라벨을 분리하여 같은 마스터 키로부터 용도가 다른 두 키를 얻는다. 마스터 키를
    두 용도에 그대로 재사용하지 않기 위한 조치다.
    """
    if len(kek) < 32:
        raise CryptoFormatError('kek must be at least 32 bytes')
    return (hmac.new(kek, KEK_ENC_LABEL, hashlib.sha256).digest(),
            hmac.new(kek, KEK_MAC_LABEL, hashlib.sha256).digest())


def wrap_key(raw_key, kek, iv=None):
    """데이터 암호화 키를 마스터 키로 감싼다. 키 식별자 자리는 0을 쓴다."""
    e, m = kek_subkeys(kek)
    return encrypt_bytes(raw_key, 0, e, m, iv)


def unwrap_key(wrapped, kek):
    e, m = kek_subkeys(kek)
    return decrypt_bytes(wrapped, e, m)


# --- 블라인드 인덱스 -------------------------------------------------------

def blind_index(plain, index_key, norm='NONE'):
    """검색용 색인 값. 키가 결합된 HMAC이므로 전수 대입으로 원문을 복원할 수 없다."""
    if plain is None:
        return None
    if len(index_key) != 32:
        raise CryptoFormatError('index_key must be 32 bytes')
    src = normalize(plain, norm).encode('utf-8')
    return hmac.new(index_key, src, hashlib.sha256).digest()


# --- 일방향 (비밀번호) -----------------------------------------------------

def pbkdf2_sha256_manual(password, salt, iterations, dklen=PWD_DK_LEN):
    """PL/SQL에 그대로 옮길 수 있는 형태의 PBKDF2 구현.

    dklen 이 해시 출력(32)과 같으므로 블록은 하나뿐이며, 반복 XOR만 수행한다.
    PL/SQL 쪽은 DBMS_CRYPTO.MAC 과 UTL_RAW.BIT_XOR 로 동일하게 구현한다.
    """
    if dklen != 32:
        raise CryptoFormatError('this variant supports dklen=32 only')
    pwd = password.encode('utf-8') if isinstance(password, str) else password
    u = hmac.new(pwd, salt + b'\x00\x00\x00\x01', hashlib.sha256).digest()
    t = u
    for _ in range(iterations - 1):
        u = hmac.new(pwd, u, hashlib.sha256).digest()
        t = bytes(a ^ b for a, b in zip(t, u))
    return t


def password_hash(password, salt=None, iterations=100000):
    """비밀번호 저장 블롭.

    빈 비밀번호는 거부한다. 저장되어서는 안 되는 값이기도 하고, 세 구현의 동작이
    갈리는 지점이기도 하다. 자바는 빈 키로 메시지 인증 코드를 계산하지 못하고,
    오라클은 빈 문자열을 널로 다루며, 파이썬만 조용히 값을 만들어 낸다.
    맞추기보다 셋 다 거부하는 편이 옳다.

    블롭 = ver(1) | kdf(1) | iterations(4, big-endian) | salt(16) | dk(32)
    반복 횟수를 블롭에 담으므로, 나중에 반복 횟수를 상향해도 기존 사용자와
    신규 사용자가 공존할 수 있다.
    """
    if password is None or password == '':
        raise CryptoFormatError('빈 비밀번호는 저장할 수 없다')
    salt = salt if salt is not None else os.urandom(PWD_SALT_LEN)
    if len(salt) != PWD_SALT_LEN:
        raise CryptoFormatError('salt must be 16 bytes')
    if not 1 <= iterations <= 0xFFFFFFFF:
        raise CryptoFormatError('iterations out of range')
    dk = pbkdf2_sha256_manual(password, salt, iterations)
    head = bytes([KDF_VERSION, KDF_PBKDF2_HMAC_SHA256]) + iterations.to_bytes(4, 'big')
    return head + salt + dk


def password_verify(password, stored):
    if password is None or password == '':
        return False
    if stored is None or len(stored) != 2 + 4 + PWD_SALT_LEN + PWD_DK_LEN:
        return False
    if stored[0] != KDF_VERSION or stored[1] != KDF_PBKDF2_HMAC_SHA256:
        return False
    iterations = int.from_bytes(stored[2:6], 'big')
    salt = stored[6:6 + PWD_SALT_LEN]
    dk = stored[6 + PWD_SALT_LEN:]
    return hmac.compare_digest(pbkdf2_sha256_manual(password, salt, iterations), dk)


# --- 유틸 ------------------------------------------------------------------

def hx(b):
    return None if b is None else b.hex().upper()


def unhx(s):
    return None if s is None else bytes.fromhex(s)


def load_vectors(path):
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)
