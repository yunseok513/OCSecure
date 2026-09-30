# -*- coding: utf-8 -*-
"""표준 라이브러리만으로 만든 AES-256 CBC.

**이것은 참조 구현 전용이다. 운영에 쓰지 말 것.**

쓰는 곳은 고정 시험 벡터를 만들고 대조하는 자리 하나뿐이다. 운영에서 실제로
암복호화를 수행하는 것은 오라클과 자바의 검증된 구현이며, 이 파일은 그것들이
내놓은 값이 규격과 맞는지 확인하는 기준으로만 쓴다.

직접 구현한 이유는 폐쇄망 때문이다. 참조 구현이 외부 패키지 하나에 매여 있으면
망이 분리된 환경으로 옮길 때마다 설치 파일을 함께 챙겨야 하고, 운영체제와
파이썬 판이 어긋나면 그마저 막힌다. 쓰는 기능이 AES-256 CBC 하나뿐이라
직접 두는 편이 낫다고 판단하였다.

직접 만든 암호 구현은 검증이 생명이므로 두 가지로 대조한다. 하나는 미국
표준문서 FIPS-197 부록 C.3 의 AES-256 시험 벡터이고, 다른 하나는 검증된
라이브러리가 설치되어 있을 때 무작위 입력으로 결과를 맞춰 보는 것이다.
두 대조 모두 tests/test_aes_pure.py 에 있다.

시간 일정성 같은 부수 경로 방어는 하지 않는다. 시험 벡터를 만드는 자리에는
필요 없고, 필요한 자리에서는 이 구현을 쓰지 않기 때문이다.
"""

# --- 유한체 연산 -----------------------------------------------------------

def _gmul(a, b):
    """GF(2^8) 곱셈. 기약다항식은 0x11B 이다."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _build_sbox():
    """치환표를 정의대로 계산한다. 256개 값을 손으로 옮겨 적다 틀리는 일을 피한다."""
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break

    sbox = [0] * 256
    for i in range(256):
        x = inv[i]
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[i] = s ^ 0x63

    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]

NB = 4
NK = 8    # 256비트 키는 32바이트, 곧 8워드
NR = 14   # 그때 라운드 수


# --- 키 확장 ---------------------------------------------------------------

def _expand_key(key):
    if len(key) != 32:
        raise ValueError('AES-256 키는 32바이트여야 한다')

    w = [list(key[4 * i:4 * i + 4]) for i in range(NK)]
    for i in range(NK, NB * (NR + 1)):
        t = list(w[i - 1])
        if i % NK == 0:
            t = t[1:] + t[:1]                      # 워드 회전
            t = [SBOX[b] for b in t]               # 바이트 치환
            t[0] ^= RCON[i // NK]
        elif i % NK == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - NK][j] ^ t[j] for j in range(4)])
    return w


# --- 블록 변환 -------------------------------------------------------------

def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r + 4 * c] ^= w[rnd * 4 + c][r]


def _sub_bytes(s, box):
    for i in range(16):
        s[i] = box[s[i]]


def _shift_rows(s):
    out = list(s)
    for r in range(1, 4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    s[:] = out


def _inv_shift_rows(s):
    out = list(s)
    for r in range(1, 4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    s[:] = out


def _mix_columns(s):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        s[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        s[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        s[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        s[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)


def _inv_mix_columns(s):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        s[4 * c + 0] = (_gmul(a[0], 14) ^ _gmul(a[1], 11)
                        ^ _gmul(a[2], 13) ^ _gmul(a[3], 9))
        s[4 * c + 1] = (_gmul(a[0], 9) ^ _gmul(a[1], 14)
                        ^ _gmul(a[2], 11) ^ _gmul(a[3], 13))
        s[4 * c + 2] = (_gmul(a[0], 13) ^ _gmul(a[1], 9)
                        ^ _gmul(a[2], 14) ^ _gmul(a[3], 11))
        s[4 * c + 3] = (_gmul(a[0], 11) ^ _gmul(a[1], 13)
                        ^ _gmul(a[2], 9) ^ _gmul(a[3], 14))


def encrypt_block(block, w):
    s = list(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, NR):
        _sub_bytes(s, SBOX)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, w, rnd)
    _sub_bytes(s, SBOX)
    _shift_rows(s)
    _add_round_key(s, w, NR)
    return bytes(s)


def decrypt_block(block, w):
    s = list(block)
    _add_round_key(s, w, NR)
    for rnd in range(NR - 1, 0, -1):
        _inv_shift_rows(s)
        _sub_bytes(s, INV_SBOX)
        _add_round_key(s, w, rnd)
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    _sub_bytes(s, INV_SBOX)
    _add_round_key(s, w, 0)
    return bytes(s)


# --- CBC 운영 모드 ---------------------------------------------------------
# 채우기는 호출하는 쪽이 이미 한 상태로 넘어온다.

def cbc_encrypt(data, key, iv):
    if len(data) % 16 != 0:
        raise ValueError('입력 길이가 블록 크기의 배수가 아니다')
    w = _expand_key(key)
    prev = bytes(iv)
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = bytes(x ^ y for x, y in zip(data[i:i + 16], prev))
        prev = encrypt_block(blk, w)
        out += prev
    return bytes(out)


def cbc_decrypt(data, key, iv):
    if len(data) % 16 != 0:
        raise ValueError('입력 길이가 블록 크기의 배수가 아니다')
    w = _expand_key(key)
    prev = bytes(iv)
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(x ^ y for x, y in zip(decrypt_block(blk, w), prev))
        prev = blk
    return bytes(out)
