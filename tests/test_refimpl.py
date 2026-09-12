# -*- coding: utf-8 -*-
"""참조 구현 시험. python3 -m unittest discover -s tests 로 실행한다."""

import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools', 'refimpl'))
import ocsecure_ref as R  # noqa: E402

EK = bytes(range(0x20, 0x40))
MK = bytes(range(0x40, 0x60))
IK = bytes(range(0x60, 0x80))
IV = bytes(range(0x10))


class TestPbkdf2(unittest.TestCase):
    def test_matches_standard_library(self):
        """수동 구현이 표준 구현과 일치해야 한다. PL/SQL 이식의 근거가 된다."""
        for pwd in ['Passw0rd!', '한글비밀번호1!', '']:
            for it in (1, 2, 1000, 4096, 10000):
                self.assertEqual(
                    R.pbkdf2_sha256_manual(pwd, b'0123456789abcdef', it),
                    hashlib.pbkdf2_hmac('sha256', pwd.encode(), b'0123456789abcdef', it, 32),
                    msg='pwd=%r it=%d' % (pwd, it))


class TestSymmetric(unittest.TestCase):
    def test_round_trip(self):
        for plain in ['880101-1234567', '홍길동', '', 'A' * 300, '탭\t줄바꿈\n포함']:
            blob = R.encrypt(plain, 1, EK, MK)
            self.assertEqual(R.decrypt(blob, EK, MK), plain)

    def test_probabilistic(self):
        """같은 평문을 두 번 암호화하면 서로 다른 암호문이 나와야 한다."""
        a = R.encrypt('880101-1234567', 1, EK, MK)
        b = R.encrypt('880101-1234567', 1, EK, MK)
        self.assertNotEqual(a, b)
        self.assertEqual(R.decrypt(a, EK, MK), R.decrypt(b, EK, MK))

    def test_header(self):
        blob = R.encrypt('x', 0xBEEF, EK, MK, IV)
        h = R.parse_header(blob)
        self.assertEqual(h['version'], R.FMT_VERSION)
        self.assertEqual(h['alg_id'], R.ALG_AES256_CBC_HMAC_SHA256)
        self.assertEqual(h['key_id'], 0xBEEF)

    def test_length_formula(self):
        """설계서에 적은 길이 산정과 실제가 일치하는지 확인한다."""
        blob = R.encrypt('880101-1234567', 1, EK, MK, IV)   # 평문 14바이트 -> 16
        self.assertEqual(len(blob), 4 + 16 + 16 + 32)
        self.assertEqual(len(blob), 68)

    def test_tamper_detected(self):
        blob = bytearray(R.encrypt('880101-1234567', 1, EK, MK, IV))
        for pos in (0, 1, 3, 5, 25, len(blob) - 1):
            bad = bytearray(blob)
            bad[pos] ^= 0x01
            with self.assertRaises(R.CryptoFormatError):
                R.decrypt(bytes(bad), EK, MK)

    def test_wrong_key_rejected_before_decrypt(self):
        blob = R.encrypt('880101-1234567', 1, EK, MK, IV)
        with self.assertRaises(R.CryptoFormatError):
            R.decrypt(blob, EK, bytes(32))

    def test_none_passthrough(self):
        self.assertIsNone(R.encrypt(None, 1, EK, MK))
        self.assertIsNone(R.decrypt(None, EK, MK))


class TestBlindIndex(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(R.blind_index('880101-1234567', IK),
                         R.blind_index('880101-1234567', IK))

    def test_normalization(self):
        """구분자 유무와 무관하게 같은 색인 값이 나와야 검색이 성립한다."""
        self.assertEqual(R.blind_index('880101-1234567', IK, 'DIGITS'),
                         R.blind_index('8801011234567', IK, 'DIGITS'))
        self.assertEqual(R.blind_index('  홍길동 ', IK, 'TRIM'),
                         R.blind_index('홍길동', IK, 'TRIM'))

    def test_key_dependent(self):
        self.assertNotEqual(R.blind_index('880101-1234567', IK),
                            R.blind_index('880101-1234567', bytes(32)))


class TestPassword(unittest.TestCase):
    def test_verify(self):
        for pw in ['Passw0rd!', '한글비밀번호1!', '']:
            stored = R.password_hash(pw, iterations=1000)
            self.assertTrue(R.password_verify(pw, stored))
            self.assertFalse(R.password_verify(pw + 'x', stored))

    def test_salted(self):
        a = R.password_hash('Passw0rd!', iterations=1000)
        b = R.password_hash('Passw0rd!', iterations=1000)
        self.assertNotEqual(a, b)

    def test_iterations_embedded(self):
        """반복 횟수를 블롭에 담으므로 서로 다른 설정이 공존할 수 있다."""
        old = R.password_hash('Passw0rd!', iterations=1000)
        new = R.password_hash('Passw0rd!', iterations=5000)
        self.assertTrue(R.password_verify('Passw0rd!', old))
        self.assertTrue(R.password_verify('Passw0rd!', new))
        self.assertEqual(int.from_bytes(old[2:6], 'big'), 1000)
        self.assertEqual(int.from_bytes(new[2:6], 'big'), 5000)


class TestKeyWrap(unittest.TestCase):
    def test_round_trip(self):
        kek = bytes(range(32))
        self.assertEqual(R.unwrap_key(R.wrap_key(EK, kek), kek), EK)

    def test_wrong_kek(self):
        with self.assertRaises(R.CryptoFormatError):
            R.unwrap_key(R.wrap_key(EK, bytes(range(32))), bytes(32))

    def test_subkeys_differ(self):
        e, m = R.kek_subkeys(bytes(range(32)))
        self.assertNotEqual(e, m)


class TestVectorFile(unittest.TestCase):
    """생성된 벡터가 현재 구현과 여전히 일치하는지 확인한다.

    구현을 고치면서 벡터를 다시 만들지 않는 사고를 막기 위한 시험이다.
    """

    @classmethod
    def setUpClass(cls):
        cls.v = R.load_vectors(os.path.join(ROOT, 'tests', 'vectors', 'kat.json'))

    def test_samples(self):
        v = self.v
        ek, mk, ik = R.unhx(v['enc_key']), R.unhx(v['mac_key']), R.unhx(v['idx_key'])
        iv, kid = R.unhx(v['iv']), v['key_id']
        for s in v['samples']:
            self.assertEqual(R.hx(R.encrypt(s['plain'], kid, ek, mk, iv)), s['cipher'], s['name'])
            self.assertEqual(R.hx(R.blind_index(s['plain'], ik, s['norm'])),
                             s['blind_index'], s['name'])
            self.assertEqual(R.decrypt(R.unhx(s['cipher']), ek, mk), s['plain'], s['name'])

    def test_wrapped_keys(self):
        v = self.v
        kek, iv = R.unhx(v['kek']), R.unhx(v['iv'])
        self.assertEqual(R.hx(R.wrap_key(R.unhx(v['enc_key']), kek, iv)), v['wrapped_enc_key'])
        self.assertEqual(R.unwrap_key(R.unhx(v['wrapped_idx_key']), kek), R.unhx(v['idx_key']))

    def test_passwords(self):
        v = self.v
        salt, it = R.unhx(v['pwd_salt']), v['pwd_iterations']
        for p in v['passwords']:
            self.assertEqual(R.hx(R.password_hash(p['plain'], salt, it)), p['stored'])
            self.assertTrue(R.password_verify(p['plain'], R.unhx(p['stored'])))


if __name__ == '__main__':
    unittest.main()
