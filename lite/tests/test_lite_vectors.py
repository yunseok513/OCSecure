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


def cp949_malformed(data):
    """Walk bytes like a CP949 decoder; count lead bytes without a valid trail byte."""
    bad, i = 0, 0
    while i < len(data):
        if data[i] < 0x80:
            i += 1
        elif i + 1 < len(data) and (0x41 <= data[i + 1] <= 0x5A or 0x61 <= data[i + 1] <= 0x7A
                                    or 0x81 <= data[i + 1] <= 0xFE):
            i += 2
        else:
            bad += 1
            i += 1
    return bad


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

    def test_code_is_ascii_and_comments_fit_cp949(self):
        """Korean is allowed in comments only, and every character must exist in CP949."""
        for path in self.files:
            name = os.path.basename(path)
            with open(path, encoding='utf-8') as fh:
                text = fh.read()
            try:
                data = text.encode('cp949')
            except UnicodeEncodeError as e:
                self.fail('%s: character not in CP949: %r' % (name, text[e.start]))
            self.assertEqual(cp949_malformed(data), 0, name)
            if name != '05_check_charset.sql':
                code = lint_plsql.strip_comments(text)
                self.assertEqual([c for c in code if ord(c) > 127], [], name + ': non-ASCII outside comments')

    def test_every_script_starts_with_charset_check(self):
        for path in self.files:
            name = os.path.basename(path)
            if name == '05_check_charset.sql':
                continue
            with open(path, 'rb') as fh:
                first = fh.readline()
            self.assertEqual(first.strip(), b'@@05_check_charset.sql', name)

    def test_charset_check_runs_before_any_non_ascii_byte(self):
        with open(os.path.join(SQL_DIR, '05_check_charset.sql'), 'rb') as fh:
            data = fh.read()
        first_non_ascii = next(i for i, c in enumerate(data) if c > 127)
        head = data[:first_non_ascii].decode('ascii')
        # Any error stops the install, so a garbled probe line cannot let the install go on.
        self.assertIn('WHENEVER SQLERROR EXIT FAILURE', head)
        code = lint_plsql.strip_comments(data.decode('utf-8'))
        self.assertIn("ASCIISTR(v_probe) <> '\\AC00'", code)
        self.assertIn('RAISE_APPLICATION_ERROR', code)
        # the probe is the only non-ASCII character in the code part
        self.assertEqual([c for c in code if ord(c) > 127], ['가'])

    def test_walker_detects_utf8_read_as_cp949(self):
        """The old failure: UTF-8 Korean read through a CP949 client."""
        utf8 = read('23_functions.sql').encode('utf-8')
        self.assertGreater(cp949_malformed(utf8), 0)

    def test_package_spec_body_agree(self):
        errs = lint_plsql.check_file(os.path.join(SQL_DIR, '22_pkg_sfc.sql'))
        self.assertEqual(errs, [])

    def test_calls_into_spec_exist(self):
        public = lint_plsql.collect_specs([os.path.join(SQL_DIR, '22_pkg_sfc.sql')])
        self.assertIn('PKG_SFC', public)
        for path in self.files:
            self.assertEqual(lint_plsql.check_calls(path, public), [], path)

    def test_no_sql_errfn_trailing_comment(self):
        public = lint_plsql.collect_specs([os.path.join(SQL_DIR, '22_pkg_sfc.sql')])
        for path in self.files:
            self.assertEqual(lint_plsql.check_sql_errfn(path), [], path)
            self.assertEqual(lint_plsql.check_trailing_comment(path), [], path)
            self.assertEqual(lint_plsql.check_local_in_sql(path, public), [], path)

    def test_every_unit_terminated(self):
        for name in ('22_pkg_sfc.sql', '23_functions.sql'):
            text = lint_plsql.strip_comments(read(name))
            creates = len(re.findall(r'^\s*CREATE\s+OR\s+REPLACE\b', text, re.I | re.M))
            slashes = len(re.findall(r'^\s*/\s*$', text, re.M))
            self.assertEqual(creates, slashes, name)

    def test_app_functions_match_connect_script(self):
        funcs = set(re.findall(r'CREATE OR REPLACE FUNCTION (\w+)', read('23_functions.sql')))
        granted = set(re.findall(r'GRANT EXECUTE ON SFC_OWNER\.(\w+)', read('40_connect_app.sql')))
        revoked = set(re.findall(r'REVOKE EXECUTE ON SFC_OWNER\.(\w+)', read('41_disconnect_app.sql')))
        self.assertEqual(funcs, granted)
        self.assertEqual(funcs, revoked)


class ManualMatchesCode(unittest.TestCase):
    """The maintenance manual must not drift from the SQL it describes."""

    manual = open(os.path.join(ROOT, 'lite', 'docs', '04_안내서.md'), encoding='utf-8').read()

    def test_function_names(self):
        funcs = set(re.findall(r'CREATE OR REPLACE FUNCTION (\w+)', read('23_functions.sql')))
        in_manual = set(re.findall(r'`(FN_SFC_[A-Z_]+)', self.manual))
        self.assertEqual(funcs, in_manual)

    def test_error_codes(self):
        spec = read('22_pkg_sfc.sql')
        defined = set(re.findall(r'CONSTANT PLS_INTEGER := (-20\d{3});', spec))
        documented = set(re.findall(r'`(-20\d{3})`', self.manual))
        self.assertEqual(defined, documented)

    def test_messages_quoted_in_manual_exist_in_code(self):
        body = read('22_pkg_sfc.sql')
        for msg in ('stored key does not match the seal', 'no active key', 'key id not found',
                    'ciphertext too short', 'not a valid hex string', 'keys already exist'):
            self.assertIn(msg, body)
            self.assertIn(msg, self.manual)

    def test_iteration_default(self):
        m = re.search(r'c_pwd_iterations CONSTANT PLS_INTEGER := (\d+);', read('22_pkg_sfc.sql'))
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


class PackageBuilder(unittest.TestCase):
    """lite/tools/make_lite_package.py builds a complete, self-consistent package."""

    @classmethod
    def setUpClass(cls):
        import subprocess
        import tempfile
        cls.tmp = tempfile.mkdtemp()
        r = subprocess.run([sys.executable, '-I', os.path.join(ROOT, 'lite', 'tools', 'make_lite_package.py'),
                            '--out', cls.tmp, '--no-zip', '--skip-tests'],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.output = r.stdout.decode('utf-8', 'replace')
        cls.rc = r.returncode
        dirs = [d for d in os.listdir(cls.tmp) if d.startswith('ocs-lite-install-')]
        cls.dest = os.path.join(cls.tmp, dirs[0]) if dirs else None

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def rel_files(self):
        out = set()
        for base, _d, files in os.walk(self.dest):
            for f in files:
                out.add(os.path.relpath(os.path.join(base, f), self.dest).replace(os.sep, '/'))
        return out

    def test_build_succeeds(self):
        self.assertEqual(self.rc, 0, self.output)
        self.assertIsNotNone(self.dest)

    def test_contents_are_exactly_the_install_set(self):
        sql = {'sql/' + f for f in os.listdir(SQL_DIR) if f.endswith('.sql')}
        want = sql | {'안내서.md', '설계결정.md', 'tools/verify_manifest.py', 'VERSION', 'MANIFEST.sha256'}
        self.assertEqual(self.rel_files(), want)

    def test_no_test_or_reference_code_inside(self):
        for rel in self.rel_files():
            self.assertNotIn('lite_ref', rel)
            self.assertNotIn('test_', rel)
            self.assertNotIn('__pycache__', rel)

    def test_manifest_matches_every_file(self):
        import hashlib
        listed = {}
        with open(os.path.join(self.dest, 'MANIFEST.sha256'), encoding='utf-8') as fh:
            for line in fh:
                if line.strip():
                    digest, rel = line.rstrip('\n').split('  ', 1)
                    listed[rel] = digest
        self.assertEqual(set(listed), self.rel_files() - {'MANIFEST.sha256'})
        for rel, digest in listed.items():
            with open(os.path.join(self.dest, rel), 'rb') as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest, rel)

    def test_packaged_sql_is_the_source_in_cp949(self):
        for f in os.listdir(SQL_DIR):
            if f.endswith('.sql'):
                with open(os.path.join(SQL_DIR, f), encoding='utf-8') as a, \
                        open(os.path.join(self.dest, 'sql', f), 'rb') as b:
                    want = a.read().replace('\r\n', '\n').encode('cp949')
                    got = b.read()
                    self.assertEqual(got, want, f)
                    self.assertEqual(cp949_malformed(got), 0, f)
        # the packaged bytes are not UTF-8: that is the point of the conversion
        with open(os.path.join(self.dest, 'sql', '23_functions.sql'), 'rb') as fh:
            with self.assertRaises(UnicodeDecodeError):
                fh.read().decode('utf-8')

    def test_unlisted_sql_file_stops_the_build(self):
        import importlib.util
        import shutil
        import tempfile
        spec = importlib.util.spec_from_file_location(
            'make_lite_package', os.path.join(ROOT, 'lite', 'tools', 'make_lite_package.py'))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fake = tempfile.mkdtemp()
        try:
            shutil.copytree(SQL_DIR, os.path.join(fake, 'sql'))
            open(os.path.join(fake, 'sql', '60_new.sql'), 'w').write('-- new\n')
            mod.LITE = fake
            with self.assertRaises(SystemExit):
                mod.check_sql_list()
        finally:
            shutil.rmtree(fake, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
