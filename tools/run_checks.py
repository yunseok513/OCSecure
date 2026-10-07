# -*- coding: utf-8 -*-
"""OCSecure 개발 점검. 윈도우와 리눅스와 맥에서 모두 동작한다.

오라클 없이 돌릴 수 있는 검증만 수행한다.

  1. 참조 구현 시험
  2. 고정 시험 벡터가 참조 구현과 일치하는지
  3. PL/SQL 정적 점검
  4. 자바 연동 모듈 컴파일과 고정 시험 벡터 대조
  5. 설치 매뉴얼이 원본(tmpl)에서 만든 것과 같은지, 언급한 경로가 있는지

실 인스턴스에서의 컴파일과 자체 시험(sql/09_test/902_selftest.sql)은 이것으로
대신할 수 없다.

실행

  python tools/run_checks.py             (윈도우는 py -3 tools/run_checks.py)
  python tools/run_checks.py --strict    건너뛴 항목도 실패로 본다
  python tools/run_checks.py --only java 자바만 컴파일하고 시험한다

외부 패키지는 필요하지 않다. 표준 라이브러리만으로 돌아가므로 폐쇄망에서도
그대로 쓸 수 있다. JDK 가 없으면 자바 항목만 건너뛴다.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 콘솔이 표현하지 못하는 글자가 섞여도 죽지 않게 한다. 죽는 것보다 물음표가 낫다.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, 'reconfigure'):
        try:
            _stream.reconfigure(errors='replace')
        except (ValueError, OSError):
            pass

VECTOR_FILES = [
    os.path.join('tests', 'vectors', 'kat.json'),
    os.path.join('tests', 'vectors', 'kat.properties'),
    os.path.join('sql', '09_test', '901_kat_data.sql'),
]

failed = []
skipped = []


def title(text):
    print('=== %s ===' % text)


def run(args, **kw):
    """자식 프로세스를 돌리고 종료 코드를 돌려준다."""
    return subprocess.call(args, cwd=ROOT, **kw)


def run_utf8(args):
    """출력을 UTF-8 로 받아 파이썬을 통해 다시 찍고 종료 코드를 돌려준다.

    자바가 콘솔에 직접 찍게 두면 문자집합이 어긋난다. 리눅스에서 로캘이 C 이면
    한글이 물음표가 되고, 한글 윈도우 콘솔은 코드 페이지가 949 라서 UTF-8 바이트를
    잘못 읽어 글자가 깨진다. 자바에는 UTF-8 로 내보내게 하고 그것을 여기서 받아
    파이썬으로 다시 찍으면, 콘솔에 맞추는 일은 파이썬이 알아서 한다.

    출력을 모았다가 한 번에 찍으므로 진행 중에는 보이지 않는다. 자바 자체 시험은
    1초 안에 끝나므로 문제가 되지 않는다.
    """
    proc = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    text = proc.stdout.decode('utf-8', errors='replace')
    if text:
        print(text, end='' if text.endswith('\n') else '\n')
    return proc.returncode


def same_content(path_a, path_b):
    """줄바꿈 차이를 뺀 내용 비교.

    형상 관리 설정에 따라 내려받은 파일이 CRLF 일 수 있다. 줄바꿈은 운영체제와
    도구가 만들어 내는 차이일 뿐 벡터의 내용이 아니므로, 그것 때문에 점검이
    실패하면 진짜 문제를 가린다.
    """
    def norm(p):
        with open(p, 'rb') as fh:
            return fh.read().replace(b'\r\n', b'\n')
    return norm(path_a) == norm(path_b)


def check_unit_tests():
    title('1. 참조 구현 시험')
    if run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-q']) != 0:
        failed.append('참조 구현 시험')
    else:
        print('  [정상] 모든 시험이 통과하였다')


def check_vectors():
    title('2. 고정 시험 벡터 최신 여부')
    backup = tempfile.mkdtemp(prefix='ocsecure-vec-')
    try:
        for rel in VECTOR_FILES:
            shutil.copy(os.path.join(ROOT, rel), backup)

        if run([sys.executable, os.path.join('tools', 'refimpl', 'gen_vectors.py')],
               stdout=subprocess.DEVNULL) != 0:
            failed.append('시험 벡터 생성')
            return

        for rel in VECTOR_FILES:
            cur = os.path.join(ROOT, rel)
            old = os.path.join(backup, os.path.basename(rel))
            if not same_content(cur, old):
                print('  [오류] %s 이(가) 참조 구현과 어긋난다.' % rel)
                print('         재생성 결과를 확인하고 함께 커밋할 것.')
                failed.append('시험 벡터 대조')
                return
        print('  [정상] 시험 벡터가 참조 구현과 일치한다')
    finally:
        # 점검은 작업 파일을 바꾸지 않는다. 다시 만들어 본 것은 대조용일 뿐이므로
        # 원래 파일을 되돌려 놓는다. 어긋난 경우에도 마찬가지이며, 갱신은
        # gen_vectors.py 를 직접 돌려 의도적으로 해야 한다.
        for rel in VECTOR_FILES:
            old = os.path.join(backup, os.path.basename(rel))
            if os.path.exists(old):
                shutil.copy(old, os.path.join(ROOT, rel))
        shutil.rmtree(backup, ignore_errors=True)


def check_plsql():
    title('3. PL/SQL 정적 점검')
    if run([sys.executable, os.path.join('tools', 'lint_plsql.py')]) != 0:
        failed.append('PL/SQL 정적 점검')


def java_sources():
    out = []
    for base, _dirs, files in os.walk(os.path.join(ROOT, 'java', 'src')):
        for f in files:
            if f.endswith('.java'):
                out.append(os.path.join(base, f))
    return sorted(out)


def check_manual():
    title('5. 매뉴얼 목차와 설치 매뉴얼 원본')
    if run([sys.executable, '-I', os.path.join('tools', 'make_toc.py'), '--check']) != 0:
        failed.append('매뉴얼 목차')
    if run([sys.executable, '-I', os.path.join('tools', 'build_manual.py'), '--check']) != 0:
        failed.append('설치 매뉴얼 원본 대조')
    if run([sys.executable, '-I', os.path.join('tools', 'check_manual_paths.py')]) != 0:
        failed.append('설치 매뉴얼 경로 대조')


def check_java():
    title('4. 자바 연동 모듈')
    if shutil.which('javac') is None or shutil.which('java') is None:
        print('  [건너뜀] javac 또는 java 를 찾을 수 없다. JDK 설치와 PATH 를 확인할 것.')
        skipped.append('자바 컴파일과 시험')
        return

    out = tempfile.mkdtemp(prefix='ocsecure-java-')
    try:
        if run(['javac', '-encoding', 'UTF-8', '-Xlint:all', '-d', out]
               + java_sources()) != 0:
            failed.append('자바 컴파일')
            return
        print('  [정상] 경고 없이 컴파일되었다')

        if run_utf8(['java', '-Dstdout.encoding=UTF-8', '-Dfile.encoding=UTF-8',
                     '-cp', out, 'ocsecure.client.OcsSelfTest',
                     os.path.join('tests', 'vectors', 'kat.properties')]) != 0:
            failed.append('자바 자체 시험')
    finally:
        shutil.rmtree(out, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description='OCSecure 개발 점검')
    ap.add_argument('--strict', action='store_true',
                    help='건너뛴 항목도 실패로 본다. 지속 통합에서 쓴다')
    ap.add_argument('--only', choices=['python', 'vectors', 'plsql', 'java', 'manual'],
                    help='한 가지만 수행한다')
    args = ap.parse_args()

    steps = {'python': check_unit_tests, 'vectors': check_vectors,
             'plsql': check_plsql, 'java': check_java, 'manual': check_manual}
    if args.only:
        steps[args.only]()
    else:
        for name in ('python', 'vectors', 'plsql', 'java', 'manual'):
            steps[name]()

    print('')
    if failed:
        print('=== 실패 %d건: %s ===' % (len(failed), ', '.join(failed)))
        return 1
    if skipped:
        print('=== 건너뜀 %d건: %s ===' % (len(skipped), ', '.join(skipped)))
        if args.strict:
            print('    --strict 이므로 실패로 처리한다.')
            return 1
        print('    나머지 점검은 모두 통과하였다.')
        return 0
    print('=== 모든 점검 통과 ===')
    return 0


if __name__ == '__main__':
    sys.exit(main())
