# -*- coding: utf-8 -*-
"""기존 비밀번호 저장 방식 식별기 시험.

식별기가 실제로 맞히는지 확인한다. 알려진 구성으로 값을 만들어 넣고 그 구성을
되짚어 내는지 보는 방식이다. 식별기가 조용히 아무것도 못 맞히는 상태로
방치되는 것을 막기 위한 시험이다.
"""

import base64
import hashlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import legacy_pwd_probe as P  # noqa: E402

PW = 'Test1234!'
UID = 'testuser'


def b64(b):
    return base64.b64encode(b).decode('ascii')


class TestKnownConstructions(unittest.TestCase):

    def assertFound(self, stored, uid=None, contains=None):
        hits = P.probe(PW if contains != 'euckr' else '한글비밀1!', stored, uid)
        self.assertTrue(hits, '식별하지 못하였다: %r' % stored)
        return hits

    def test_sha256_base64(self):
        hits = self.assertFound(b64(hashlib.sha256(PW.encode()).digest()))
        self.assertTrue(any('SHA256' in h and 'Base64' in h for h in hits), hits)

    def test_sha256_hex(self):
        self.assertFound(hashlib.sha256(PW.encode()).hexdigest())

    def test_sha1_hex(self):
        self.assertFound(hashlib.sha1(PW.encode()).hexdigest())

    def test_md5_hex_upper(self):
        self.assertFound(hashlib.md5(PW.encode()).hexdigest().upper())

    def test_sha512_base64(self):
        self.assertFound(b64(hashlib.sha512(PW.encode()).digest()))

    def test_id_prefixed(self):
        """아이디를 솔트처럼 쓰는 구성. 국내 시스템에서 드물지 않다."""
        stored = b64(hashlib.sha256((UID + PW).encode()).digest())
        hits = self.assertFound(stored, UID)
        self.assertTrue(any('아이디 + 비밀번호' in h for h in hits), hits)

    def test_id_suffixed(self):
        stored = b64(hashlib.sha256((PW + UID).encode()).digest())
        hits = self.assertFound(stored, UID)
        self.assertTrue(any('비밀번호 + 아이디' in h for h in hits), hits)

    def test_id_needed(self):
        """아이디를 넣지 않으면 아이디가 섞인 구성은 맞히지 못한다."""
        stored = b64(hashlib.sha256((UID + PW).encode()).digest())
        self.assertEqual(P.probe(PW, stored, None), [])

    def test_double_hash(self):
        stored = hashlib.sha256(hashlib.sha256(PW.encode()).digest()).hexdigest()
        hits = self.assertFound(stored)
        self.assertTrue(any('두 번' in h for h in hits), hits)

    def test_double_hash_via_hex(self):
        inner = hashlib.sha256(PW.encode()).hexdigest()
        stored = hashlib.sha256(inner.encode('ascii')).hexdigest()
        hits = self.assertFound(stored)
        self.assertTrue(any('16진 문자열 경유' in h for h in hits), hits)

    def test_euckr_charset(self):
        """한글 비밀번호는 문자집합에 따라 값이 달라진다."""
        pw = '한글비밀1!'
        stored = b64(hashlib.sha256(pw.encode('euc-kr')).digest())
        hits = P.probe(pw, stored, None)
        self.assertTrue(any('euc-kr' in h for h in hits), hits)

    def test_whitespace_tolerated(self):
        stored = '  ' + hashlib.sha256(PW.encode()).hexdigest() + '\n'
        self.assertTrue(P.probe(PW, stored, None))


class TestPlaintext(unittest.TestCase):

    def test_plain(self):
        hits = P.probe(PW, PW, None)
        self.assertTrue(any('평문 저장' in h for h in hits), hits)

    def test_plain_base64(self):
        hits = P.probe(PW, b64(PW.encode()), None)
        self.assertTrue(any('평문' in h for h in hits), hits)

    def test_plain_hex(self):
        hits = P.probe(PW, PW.encode().hex(), None)
        self.assertTrue(any('평문' in h for h in hits), hits)


class TestShapeAnalysis(unittest.TestCase):
    """맞히지 못했을 때 남기는 단서가 쓸모 있는지 확인한다."""

    def test_bcrypt(self):
        notes = P.describe_shape('$2a$10$' + 'x' * 53)
        self.assertTrue(any('bcrypt' in n for n in notes), notes)

    def test_prefixed(self):
        notes = P.describe_shape('{bcrypt}$2a$10$abc')
        self.assertTrue(any('접두사' in n for n in notes), notes)

    def test_hex_length_hint(self):
        notes = P.describe_shape('a' * 64)
        self.assertTrue(any('32바이트' in n for n in notes), notes)

    def test_base64_length_hint(self):
        notes = P.describe_shape(b64(bytes(32)))
        self.assertTrue(any('32' in n for n in notes), notes)

    def test_unknown(self):
        notes = P.describe_shape('비밀번호123')
        self.assertTrue(any('평문' in n for n in notes), notes)


if __name__ == '__main__':
    unittest.main()
