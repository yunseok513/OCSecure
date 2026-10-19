# -*- coding: utf-8 -*-
"""Checks for the lite module that need no Oracle instance.

1. The fixed vectors embedded in lite/sql/50_selftest.sql equal the values
   computed by the Python reference (lite_ref.py).
2. The reference itself round-trips and rejects tampering.
3. Static checks of lite/sql: ASCII only, package spec/body agree, no trailing
   comments after top-level statements, no SQLCODE inside SQL statements.
   These reuse the functions of tools/lint_plsql.py; they do not replace
   compiling and running 50_selftest.sql on a real instance.

Run:  python3 -I -m unittest discover -s lite/tests
"""

import glob
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import lite_ref  # noqa: E402
import lint_plsql  # noqa: E402

SQL_DIR = os.path.join(ROOT, 'lite', 'sql')


def read(name):
    with open(os.path.join(SQL_DIR, name), encoding='utf-8') as f:
        return f.read()


class VectorsInSelftest(unittest.TestCase):
    """Every expected value in the SQL self test must equal the Python value."""

    def test_vectors_match(self):
        sql = read('50_selftest.sql')
        v = lite_ref.vectors()
        pairs = {
            'e_derive': v['DERIVE_ENC'], 'e_rrn': v['PACK_RRN'], 'e_ko': v['PACK_KO'],
            'e_wrap': v['WRAP_ROOT'], 'e_pwd': v['PWD'],
        }
        for name, want in pairs.items():
            m = re.search(r"\b%s\s+CONSTANT\s+VARCHAR2\(\d+\)\s*:=\s*'([0-9A-F]+)'" % name, sql)
            self.assertIsNotNone(m, name + ' not found in 50_selftest.sql')
            self.assertEqual(m.group(1), want, name)
        self.assertIn("HEXTORAW('%s')" % v['ROOT'], sql)
        self.assertIn("HEXTORAW('%s')" % v['SEAL'], sql)

    def test_declared_lengths_fit(self):
        sql = read('50_selftest.sql')
        found = re.findall(r"\b(e_\w+)\s+CONSTANT\s+VARCHAR2\((\d+)\)\s*:=\s*'([0-9A-F]+)'", sql)
        self.assertEqual(len(found), 5)
        for name, size, value in found:
            self.assertLessEqual(len(value), int(size), name)


class Reference(unittest.TestCase):
    def test_round_trip(self):
        root = os.urandom(32)
        for plain in ('9001011234567', u'한글', 'x' * 100, '110-1234-5678-90'):
            blob = lite_ref.pack_with_root(root, 3, plain)
            self.assertEqual(lite_ref.unpack_with_root(root, blob), plain)

    def test_hex_lengths_match_design_table(self):
        root = bytes(32)
        hex_len = lambda s: len(lite_ref.pack_with_root(root, 1, s)) * 2
        self.assertEqual(hex_len('9001011234567'), 136)      # 13 chars
        self.assertEqual(hex_len('900101-1234567'), 136)     # 14 chars
        self.assertEqual(hex_len('a' * 20), 168)              # account, 20 chars
        self.assertEqual(hex_len('a' * 32), 200)              # account, 32 chars
        self.assertEqual(len(lite_ref.pwd_hash('pw', bytes(16), 1)) * 2, 108)

    def test_tamper_rejected(self):
        root = os.urandom(32)
        blob = bytearray(lite_ref.pack_with_root(root, 3, 'secret'))
        blob[20] ^= 1
        with self.assertRaises(Exception):
            lite_ref.unpack_with_root(root, bytes(blob))

    def test_wrap_unwrap(self):
        root, seal = os.urandom(32), os.urandom(32)
        self.assertEqual(lite_ref.unwrap_root(lite_ref.wrap_root(root, seal), seal), root)
        with self.assertRaises(Exception):
            lite_ref.unwrap_root(lite_ref.wrap_root(root, seal), os.urandom(32))

    def test_password(self):
        h = lite_ref.pwd_hash('pw', bytes(16), 5)
        self.assertTrue(lite_ref.ref.password_verify('pw', h))
        self.assertFalse(lite_ref.ref.password_verify('pw2', h))


class StaticChecks(unittest.TestCase):
    files = sorted(glob.glob(os.path.join(SQL_DIR, '*.sql')))

    def test_ascii_only(self):
        for path in self.files:
            with open(path, 'rb') as f:
                data = f.read()
            try:
                data.decode('ascii')
            except UnicodeDecodeError as e:
                self.fail('%s has non-ASCII bytes at %d' % (os.path.basename(path), e.start))

    def test_package_spec_body_agree(self):
        errs = lint_plsql.check_file(os.path.join(SQL_DIR, '22_pkg_lite.sql'))
        self.assertEqual(errs, [])

    def test_calls_into_spec_exist(self):
        public = lint_plsql.collect_specs([os.path.join(SQL_DIR, '22_pkg_lite.sql')])
        self.assertIn('PKG_LITE', public)
        for path in self.files:
            self.assertEqual(lint_plsql.check_calls(path, public), [], path)

    def test_no_sql_errfn_trailing_comment(self):
        public = lint_plsql.collect_specs([os.path.join(SQL_DIR, '22_pkg_lite.sql')])
        for path in self.files:
            self.assertEqual(lint_plsql.check_sql_errfn(path), [], path)
            self.assertEqual(lint_plsql.check_trailing_comment(path), [], path)
            self.assertEqual(lint_plsql.check_local_in_sql(path, public), [], path)

    def test_every_unit_terminated(self):
        for name in ('22_pkg_lite.sql', '23_functions.sql'):
            text = lint_plsql.strip_comments(read(name))
            creates = len(re.findall(r'^\s*CREATE\s+OR\s+REPLACE\b', text, re.I | re.M))
            slashes = len(re.findall(r'^\s*/\s*$', text, re.M))
            self.assertEqual(creates, slashes, name)

    def test_app_functions_match_connect_script(self):
        funcs = set(re.findall(r'CREATE OR REPLACE FUNCTION (\w+)', read('23_functions.sql')))
        granted = set(re.findall(r'GRANT EXECUTE ON LITE_OWNER\.(\w+)', read('40_connect_app.sql')))
        revoked = set(re.findall(r'REVOKE EXECUTE ON LITE_OWNER\.(\w+)', read('41_disconnect_app.sql')))
        self.assertEqual(funcs, granted)
        self.assertEqual(funcs, revoked)


class ManualMatchesCode(unittest.TestCase):
    """The maintenance manual must not drift from the SQL it describes."""

    manual = open(os.path.join(ROOT, 'lite', 'docs', '04_안내서.md'), encoding='utf-8').read()

    def test_function_names(self):
        funcs = set(re.findall(r'CREATE OR REPLACE FUNCTION (\w+)', read('23_functions.sql')))
        in_manual = set(re.findall(r'`(LITE_[A-Z_]+)', self.manual)) - {'LITE_KEY', 'LITE_SEAL',
                                                                        'LITE_OWNER', 'LITE_KEY_SEQ'}
        self.assertEqual(funcs, in_manual)

    def test_error_codes(self):
        spec = read('22_pkg_lite.sql')
        defined = set(re.findall(r'CONSTANT PLS_INTEGER := (-20\d{3});', spec))
        documented = set(re.findall(r'`(-20\d{3})`', self.manual))
        self.assertEqual(defined, documented)

    def test_messages_quoted_in_manual_exist_in_code(self):
        body = read('22_pkg_lite.sql')
        for msg in ('stored key does not match the seal', 'no active key', 'key id not found',
                    'ciphertext too short', 'not a valid hex string', 'keys already exist'):
            self.assertIn(msg, body)
            self.assertIn(msg, self.manual)

    def test_iteration_default(self):
        m = re.search(r'c_pwd_iterations CONSTANT PLS_INTEGER := (\d+);', read('22_pkg_lite.sql'))
        self.assertIn('(기본 %s)' % m.group(1), self.manual)

    def test_files_named_in_manual_exist(self):
        for name in set(re.findall(r'`?@?(\d\d_\w+\.sql)', self.manual)):
            self.assertTrue(os.path.exists(os.path.join(SQL_DIR, name)), name)

    def test_column_lengths_match_reference(self):
        root = bytes(32)
        n = lambda s: len(lite_ref.pack_with_root(root, 1, s)) * 2
        for want, plain in ((136, 'a' * 13), (168, 'a' * 20), (200, 'a' * 32)):
            self.assertEqual(n(plain), want)
            self.assertIn(str(want), self.manual)


if __name__ == '__main__':
    unittest.main()
