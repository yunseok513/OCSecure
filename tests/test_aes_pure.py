# -*- coding: utf-8 -*-
"""직접 만든 AES 구현 시험.

직접 구현한 암호는 검증이 생명이므로 두 가지로 대조한다. 하나는 미국 표준문서
FIPS-197 부록 C.3 의 AES-256 공인 시험 벡터이고, 다른 하나는 검증된 라이브러리가
설치되어 있을 때 무작위 입력으로 결과를 맞춰 보는 것이다.

이 구현은 참조 구현이 시험 벡터를 만들 때만 쓰인다. 운영에서 실제 암복호화를
수행하는 것은 오라클과 자바의 검증된 구현이다.
"""

import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools', 'refimpl'))
import aes_pure as A          # noqa: E402
import ocsecure_ref as R      # noqa: E402

# FIPS-197 부록 C.3 (AES-256)
FIPS_KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f'
                         '101112131415161718191a1b1c1d1e1f')
FIPS_PT = bytes.fromhex('00112233445566778899aabbccddeeff')
FIPS_CT = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')


class TestKnownAnswer(unittest.TestCase):

    def test_fips197_encrypt(self):
        w = A._expand_key(FIPS_KEY)
        self.assertEqual(A.encrypt_block(FIPS_PT, w), FIPS_CT)

    def test_fips197_decrypt(self):
        w = A._expand_key(FIPS_KEY)
        self.assertEqual(A.decrypt_block(FIPS_CT, w), FIPS_PT)

    def test_sbox_is_an_involution_pair(self):
        """치환표와 그 역표가 서로를 되돌리는지. 표를 계산으로 만들므로 함께 확인한다."""
        for i in range(256):
            self.assertEqual(A.INV_SBOX[A.SBOX[i]], i)

    def test_sbox_is_a_permutation(self):
        self.assertEqual(sorted(A.SBOX), list(range(256)))


class TestCbc(unittest.TestCase):

    KEY = bytes(range(32))
    IV = bytes(range(16))

    def test_round_trip(self):
        for n in (1, 2, 3, 16):
            data = bytes((i * 7) % 256 for i in range(n * 16))
            ct = A.cbc_encrypt(data, self.KEY, self.IV)
            self.assertEqual(len(ct), len(data))
            self.assertEqual(A.cbc_decrypt(ct, self.KEY, self.IV), data)

    def test_chaining_actually_chains(self):
        """같은 블록이 반복되어도 암호문은 달라야 한다. ECB 로 잘못 만든 경우를 잡는다."""
        data = bytes(16) * 2
        ct = A.cbc_encrypt(data, self.KEY, self.IV)
        self.assertNotEqual(ct[:16], ct[16:])

    def test_rejects_unaligned(self):
        with self.assertRaises(ValueError):
            A.cbc_encrypt(b'x' * 17, self.KEY, self.IV)

    def test_rejects_bad_key_length(self):
        with self.assertRaises(ValueError):
            A.cbc_encrypt(bytes(16), bytes(16), self.IV)


@unittest.skipUnless(R.HAVE_CRYPTOGRAPHY, '검증된 라이브러리가 없어 대조를 건너뛴다')
class TestAgainstLibrary(unittest.TestCase):
    """검증된 라이브러리와 무작위 입력으로 대조한다."""

    def test_random_cases(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        rnd = random.Random(20260930)
        for _ in range(200):
            key = bytes(rnd.getrandbits(8) for _ in range(32))
            iv = bytes(rnd.getrandbits(8) for _ in range(16))
            data = bytes(rnd.getrandbits(8)
                         for _ in range(rnd.choice([1, 2, 3, 8]) * 16))
            enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            expected = enc.update(data) + enc.finalize()
            self.assertEqual(A.cbc_encrypt(data, key, iv), expected)
            self.assertEqual(A.cbc_decrypt(expected, key, iv), data)


class TestSameVectorsEitherWay(unittest.TestCase):
    """어느 경로로 돌든 참조 구현이 같은 값을 내야 한다.

    이것이 보장되지 않으면 폐쇄망에서 만든 벡터와 개방망에서 만든 벡터가
    달라지고, 세 구현 대조의 기준 자체가 흔들린다.
    """

    def setUp(self):
        self.saved = R.FORCE_PURE

    def tearDown(self):
        R.FORCE_PURE = self.saved

    def _sample(self):
        ek, mk = bytes(range(32)), bytes(range(32, 64))
        iv = bytes(range(16))
        out = []
        for plain in ('880101-1234567', '홍길동', 'A' * 100, ''):
            out.append(R.hx(R.encrypt(plain, 1, ek, mk, iv)))
        return out

    @unittest.skipUnless(R.HAVE_CRYPTOGRAPHY, '라이브러리가 없어 비교 대상이 없다')
    def test_identical(self):
        R.FORCE_PURE = False
        with_lib = self._sample()
        R.FORCE_PURE = True
        with_pure = self._sample()
        self.assertEqual(with_lib, with_pure)

    def test_decrypt_across_paths(self):
        """한쪽으로 암호화한 것을 다른 쪽으로 풀 수 있어야 한다."""
        ek, mk = bytes(range(32)), bytes(range(32, 64))
        R.FORCE_PURE = True
        blob = R.encrypt('교차 확인', 1, ek, mk)
        R.FORCE_PURE = False
        self.assertEqual(R.decrypt(blob, ek, mk), '교차 확인')


if __name__ == '__main__':
    unittest.main()
