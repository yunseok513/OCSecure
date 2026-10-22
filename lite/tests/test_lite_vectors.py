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
            creates = len(re.findall(r'^\s*CREATE\s+OR\s+REPLACE\b', text, re.I | re.M)) \
                + len(re.findall(r'^DECLARE\b', text, re.M))
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


class ReviewFindings(unittest.TestCase):
    """Regression tests for the external review (2026-10-20)."""

    manual = open(os.path.join(ROOT, 'lite', 'docs', '04_안내서.md'), encoding='utf-8').read()

    def test_install_scripts_never_reset_exit_on_error(self):
        # 05 turns on exit-on-error and must not turn it off again
        code = lint_plsql.strip_comments(read('05_check_charset.sql'))
        self.assertIn('WHENEVER SQLERROR EXIT FAILURE', code)
        self.assertNotIn('WHENEVER SQLERROR CONTINUE', code)
        for name in sorted(os.listdir(SQL_DIR)):
            if name.endswith('.sql'):
                self.assertNotIn('WHENEVER SQLERROR CONTINUE', read(name), name)

    def test_compile_errors_stop_the_install(self):
        for name in ('22_pkg_sfc.sql', '23_functions.sql'):
            code = lint_plsql.strip_comments(read(name))
            self.assertIn("FROM user_errors", code, name)
            self.assertIn("attribute = 'ERROR'", code, name)
            self.assertIn('RAISE_APPLICATION_ERROR(-20998', code, name)

    def test_selftest_ends_with_an_error_when_a_check_fails(self):
        code = lint_plsql.strip_comments(read('50_selftest.sql'))
        self.assertIn('RAISE_APPLICATION_ERROR(-20990', code)
        self.assertLess(code.index('SELFTEST FAILED'), code.index('RAISE_APPLICATION_ERROR(-20990'))

    def test_password_iteration_fence(self):
        code = lint_plsql.strip_comments(read('22_pkg_sfc.sql'))
        m = re.search(r'c_pwd_iter_max\s+CONSTANT PLS_INTEGER := (\d+);', code)
        self.assertIsNotNone(m)
        self.assertGreater(int(m.group(1)), 600000)           # room above the usual recommendation
        self.assertGreaterEqual(code.count('v_iter > c_pwd_iter_max'), 2)   # hash and verify
        self.assertIn('c_pwd_iter_max', read('50_selftest.sql'))
        self.assertIn(m.group(1), self.manual)

    def test_forged_iteration_vector_is_well_formed(self):
        """The selftest builds a 54-byte stored value with 0x7FFFFFFF rounds."""
        sql = read('50_selftest.sql')
        m = re.search(r"pwd_verify_hex\('x', '(01017FFFFFFF[0-9A-F]+)' \|\| RPAD\('0', (\d+), '0'\)\) = 0", sql)
        self.assertIsNotNone(m)
        self.assertEqual((len(m.group(1)) + int(m.group(2))) // 2, 54)

    def test_manual_verification_sql_catches_unconverted_rows(self):
        # NULL on either side must be counted: DECODE treats two NULLs as equal and anything else as different
        self.assertIn('DECODE(FN_SFC_DEC(rrn_enc), rrn, 0, 1) = 1', self.manual)
        self.assertNotIn('FN_SFC_DEC(rrn_enc) <> rrn', self.manual)
        self.assertNotIn('rrn IS NOT NULL\n   AND', self.manual)

    def test_manual_does_not_claim_protection_after_decryption(self):
        self.assertNotIn('화면이나 로그로의 노출이 이에 해당', self.manual)
        self.assertIn('복호화한 뒤 화면, 파일, 로그에 출력한 내용은 보호하지 않습니다', self.manual)
        with open(os.path.join(ROOT, 'lite', 'docs', '02_설계결정.md'), encoding='utf-8') as fh:
            self.assertNotIn('화면이나 로그에 노출되는 경우가 이에 해당', fh.read())

    def test_manual_asks_for_the_four_acceptance_checks(self):
        for phrase in ('여섯 함수를 호출해 보았다', '재기동한 뒤 기존 암호문이 복호화된다',
                       '키를 교체한 뒤 이전 암호문과 새 암호문이 모두 복호화된다',
                       '복구한 별도 시험 데이터베이스'):
            self.assertIn(phrase, self.manual)


class SecondReviewFindings(unittest.TestCase):
    """Regression tests for the second external review (2026-10-20)."""

    manual = open(os.path.join(ROOT, 'lite', 'docs', '04_안내서.md'), encoding='utf-8').read()

    def test_decode_semantics_match_the_claim(self):
        """Model of Oracle DECODE(expr, search, 0, 1) = 1 over the four NULL combinations."""
        def decode_differs(dec, rrn):          # None stands for NULL; DECODE treats NULL = NULL
            return 0 if dec == rrn else 1
        self.assertEqual(decode_differs(None, None), 0)          # nothing to convert, nothing stored
        self.assertEqual(decode_differs(None, '9001011234567'), 1)   # not converted
        self.assertEqual(decode_differs('9001011234567', None), 1)   # original removed, ciphertext left
        self.assertEqual(decode_differs('9001011234567', '9001011234567'), 0)
        self.assertEqual(decode_differs('9001011234568', '9001011234567'), 1)

    def test_conversion_is_limited_to_the_write_stopped_procedure(self):
        self.assertIn('쓰기를 멈춘 상태에서', self.manual)
        self.assertNotIn('멈출 수 없다면 응용을 바꾼 직후', self.manual)
        self.assertIn('쓰기를 재개하기 전에', self.manual)

    def test_recompile_procedure_mentions_session_state(self):
        self.assertIn('ORA-04068', self.manual)
        self.assertIn('연결 풀', self.manual)
        self.assertNotIn('다시 컴파일해도 안전합니다', self.manual)
        self.assertIn('키와 저장된 자료는 그대로', self.manual)
        # the claim only holds because the package really keeps per-session state
        self.assertIn('g_cache', read('22_pkg_sfc.sql'))

    def test_compatibility_with_full_edition_is_not_overstated(self):
        with open(os.path.join(ROOT, 'lite', 'docs', '03_구성설계.md'), encoding='utf-8') as fh:
            doc = fh.read()
        self.assertNotIn('데이터를 변환하지 않아도 됩니다', doc)
        self.assertIn('자동으로 호환된다는 뜻은 아닙니다', doc)
        self.assertNotIn('서로 옮길 수 있습니다', read('22_pkg_sfc.sql'))


class OracleAcceptanceScripts(unittest.TestCase):
    """lite/tests/oracle/*.sql are run by hand on a test instance. They cannot be compiled here,
    so guard against the mistakes that can be seen without Oracle."""

    dir = os.path.join(ROOT, 'lite', 'tests', 'oracle')
    names = sorted(f for f in os.listdir(dir) if f.endswith('.sql')) if os.path.isdir(dir) else []

    def text(self, name):
        with open(os.path.join(self.dir, name), encoding='utf-8') as fh:
            return fh.read()

    def test_scripts_exist(self):
        self.assertEqual([n[:2] for n in self.names], ['T1', 'T2', 'T3', 'T4', 'T5', 'T6'])

    def test_ascii_only_so_nls_lang_does_not_matter(self):
        for n in self.names:
            with open(os.path.join(self.dir, n), 'rb') as fh:
                fh.read().decode('ascii')

    def test_no_subquery_inside_a_plsql_expression(self):
        """PLS-00405: a subquery is not allowed in an expression, only as SELECT ... INTO."""
        for n in self.names:
            code = lint_plsql.strip_comments(self.text(n))
            for m in re.finditer(r'(chk|PUT_LINE|TO_CHAR)\s*\(', code):
                depth, i, call = 1, m.end(), ''
                while i < len(code) and depth:
                    depth += {'(': 1, ')': -1}.get(code[i], 0)
                    call += code[i]
                    i += 1
                self.assertNotRegex(call, r'\(\s*SELECT\b', n + ': ' + call[:60])

    def test_no_privileged_views(self):
        for n in self.names:
            self.assertNotRegex(self.text(n), r'(?i)\bv\$|\bdba_', n)

    def test_scripts_stop_on_error_and_raise_on_failure(self):
        for n in self.names:
            code = lint_plsql.strip_comments(self.text(n))
            self.assertIn('WHENEVER SQLERROR EXIT FAILURE', code, n)
        for n in ('T1_decode_check.sql', 'T2_app_calls.sql', 'T4_rotate_key.sql', 'T5_verify_after.sql'):
            self.assertIn('RAISE_APPLICATION_ERROR(-20990', self.text(n), n)

    def test_t1_tests_the_query_printed_in_the_manual(self):
        manual = open(os.path.join(ROOT, 'lite', 'docs', '04_안내서.md'), encoding='utf-8').read()
        clause = 'DECODE(FN_SFC_DEC(rrn_enc), rrn, 0, 1) = 1'
        self.assertIn(clause, manual)
        self.assertIn(clause, self.text('T1_decode_check.sql'))

    def test_t1_expected_rows(self):
        """The five rows of T1 and the ids they must produce, modelled with DECODE semantics."""
        rows = {1: ('9001011234567', '9001011234567'), 2: ('9001011234568', None),
                3: (None, '9001011234569'), 4: ('9001011234570', '9001011234571'), 5: (None, None)}
        flagged = [i for i, (rrn, dec) in rows.items() if (0 if dec == rrn else 1) == 1]
        self.assertEqual(flagged, [2, 3, 4])
        self.assertIn("'2,3,4'", self.text('T1_decode_check.sql'))

    def test_t2_refuses_the_two_misuses_that_look_like_module_defects(self):
        t2 = self.text('T2_app_calls.sql')
        self.assertIn("SESSION_USER') = 'SFC_OWNER'", t2)
        self.assertIn('session_privs', t2)
        self.assertIn('SELECT ANY TABLE', t2)
        self.assertIn('EXECUTE ANY PROCEDURE', t2)
        self.assertGreaterEqual(t2.count('RAISE_APPLICATION_ERROR(-20991'), 2)
        # the guards come before the first check
        self.assertLess(t2.index('-20991'), t2.index("chk('C1"))

    def test_runbook_tells_which_schema_runs_t2(self):
        with open(os.path.join(self.dir, 'README.md'), encoding='utf-8') as fh:
            r = fh.read()
        self.assertIn('소유 계정(`SFC_OWNER`)이 아닌 업무 스키마', r)
        self.assertIn('SFC_T_APP', r)

    def test_t4_is_marked_test_only_and_irreversible(self):
        t4 = self.text('T4_rotate_key.sql')
        self.assertIn('TEST INSTANCE ONLY', t4)
        self.assertIn('CANNOT be undone', t4)

    def test_t2_negative_checks_do_not_fail_for_the_wrong_reason(self):
        """The refused calls must not be type errors that would fail even with privileges."""
        t2 = self.text('T2_app_calls.sql')
        self.assertIn('n := SFC_OWNER.PKG_SFC.is_ready', t2)
        self.assertIn('r := SFC_OWNER.SFC_SEAL.get_seal', t2)
        self.assertNotIn('PUT(SFC_OWNER', t2)


class MeasuredPasswordTiming(unittest.TestCase):
    """The measured times reported from the test instance must be recorded the same way in both documents."""

    def test_measurements_are_recorded_consistently(self):
        manual = open(os.path.join(ROOT, 'lite', 'docs', '04_안내서.md'), encoding='utf-8').read()
        record = open(os.path.join(ROOT, 'lite', 'docs', '05_검증기록.md'), encoding='utf-8').read()
        for t in ('0.48초', '5.10초', '31.11초'):
            self.assertIn(t, manual)
            self.assertIn(t, record)

    def test_measurements_are_proportional_to_the_iteration_count(self):
        """Sanity check of the reported figures: about 50 microseconds per round at every size."""
        for n, secs in ((10000, 0.48), (100000, 5.10), (600000, 31.11)):
            self.assertAlmostEqual(secs / n * 1e6, 50, delta=5)


if __name__ == '__main__':
    unittest.main()
