# -*- coding: utf-8 -*-
"""OCS-LITE 설치 패키지 만들기.

외부에 전달할 간이판 설치 패키지를 만든다. 담을 파일을 아래 목록에 하나하나
적어 두는 방식이므로 목록에 없는 파일(설계 기록, 시험 코드, 참조 구현)은 저장소에
있어도 패키지에 들어가지 않는다. lite/sql/ 에 새 파일을 만들었는데 아래 목록에도
제외 목록에도 없으면 만들기를 중단한다. 빠뜨린 채 나가는 것을 막기 위해서다.

  python3 lite/tools/make_lite_package.py
  python3 lite/tools/make_lite_package.py --no-zip

패키지 구성
  안내서.md          lite/docs/04_안내서.md (설치와 유지보수 안내서)
  설계결정.md        lite/docs/02_설계결정.md (방어 한계와 고객 고지 문안)
  sql/               설치 스크립트 (ASCII 만 쓰므로 CP949 사본이 필요 없다)
  tools/verify_manifest.py   온전성 확인 (전체판의 도구를 그대로 쓴다)
  VERSION, MANIFEST.sha256

만들기 전에 lite/tests 를 돌려 통과하지 않으면 중단한다. 이 시험은 안내서와 SQL 이
어긋나지 않았는지도 확인한다. 오라클에서의 컴파일과 자체 시험을 대신하지는 못한다.
"""

import argparse
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LITE = os.path.join(ROOT, 'lite')

# 원본 경로 -> 패키지 안 경로
FILES = {
    os.path.join('lite', 'docs', '04_안내서.md'): '안내서.md',
    os.path.join('lite', 'docs', '02_설계결정.md'): '설계결정.md',
    os.path.join('tools', 'verify_manifest.py'): os.path.join('tools', 'verify_manifest.py'),
}

# 설치에 쓰는 SQL. 번호 순서가 곧 실행 순서다.
SQL_FILES = [
    '10_sys_setup.sql',
    '20_key_table.sql',
    '21_seal.sql',
    '22_pkg_sfc.sql',
    '23_functions.sql',
    '30_init_key.sql',
    '40_connect_app.sql',
    '41_disconnect_app.sql',
    '50_selftest.sql',
    '90_uninstall.sql',
]

# lite/sql 에 있어도 패키지에 담지 않는 파일. 지금은 없다.
SQL_EXCLUDED = set()


def log(msg):
    print('  ' + msg)


def fail(msg):
    raise SystemExit('[오류] ' + msg)


def check_sql_list():
    on_disk = {f for f in os.listdir(os.path.join(LITE, 'sql')) if f.endswith('.sql')}
    listed = set(SQL_FILES)
    missing = sorted(listed - on_disk)
    unlisted = sorted(on_disk - listed - SQL_EXCLUDED)
    if missing:
        fail('목록에 있으나 파일이 없다: ' + ', '.join(missing))
    if unlisted:
        fail('lite/sql 에 있으나 담을 목록에도 제외 목록에도 없다: %s '
             '(make_lite_package.py 의 SQL_FILES 또는 SQL_EXCLUDED 에 적을 것)' % ', '.join(unlisted))


def run_tests():
    cmd = [sys.executable, '-W', 'ignore', '-I', '-m', 'unittest', 'discover',
           '-s', os.path.join(LITE, 'tests')]
    r = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    tail = r.stdout.decode('utf-8', 'replace').strip().splitlines()[-3:]
    if r.returncode != 0:
        print('\n'.join(tail))
        fail('lite/tests 가 통과하지 않아 패키지를 만들지 않는다.')
    ran = next((l.strip() for l in tail if l.startswith('Ran ')), '')
    log('[정상] lite/tests 통과' + (' (%s)' % ran if ran else ''))


def copy(rel_src, dest, rel_dst):
    src = os.path.join(ROOT, rel_src)
    if not os.path.isfile(src):
        fail('담을 파일이 없다: ' + rel_src)
    dst = os.path.join(dest, rel_dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    # 줄바꿈을 LF 로 맞춘다. 해시가 만든 장비에 따라 달라지지 않게 하기 위해서다.
    with open(src, 'rb') as fh:
        data = fh.read().replace(b'\r\n', b'\n')
    with open(dst, 'wb') as fh:
        fh.write(data)


def git_rev():
    try:
        out = subprocess.check_output(['git', '-C', ROOT, 'rev-parse', '--short', 'HEAD'],
                                      stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return 'unknown'


def git_dirty():
    try:
        out = subprocess.check_output(['git', '-C', ROOT, 'status', '--porcelain', '--', 'lite', 'tools'],
                                      stderr=subprocess.DEVNULL)
        return bool(out.strip())
    except Exception:
        return False


def write_manifest(dest):
    rows = []
    for base, dirs, files in os.walk(dest):
        dirs.sort()
        for f in sorted(files):
            full = os.path.join(base, f)
            rel = os.path.relpath(full, dest).replace(os.sep, '/')
            if rel == 'MANIFEST.sha256':
                continue
            with open(full, 'rb') as fh:
                rows.append('%s  %s' % (hashlib.sha256(fh.read()).hexdigest(), rel))
    with open(os.path.join(dest, 'MANIFEST.sha256'), 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(rows) + '\n')
    log('[정상] 파일 %d개의 해시 목록을 만들었다' % len(rows))


def check_manual_paths(dest):
    """안내서가 이름으로 부르는 SQL 파일이 패키지에 모두 있는지 본다."""
    with open(os.path.join(dest, '안내서.md'), encoding='utf-8') as fh:
        text = fh.read()
    names = set(re.findall(r'@?(\d\d_\w+\.sql)', text))
    absent = sorted(n for n in names if not os.path.isfile(os.path.join(dest, 'sql', n)))
    if absent:
        fail('안내서가 언급하나 패키지에 없는 파일: ' + ', '.join(absent))
    log('[정상] 안내서가 언급한 SQL 파일 %d개가 모두 패키지에 있다' % len(names))


def check_ascii(dest):
    for f in os.listdir(os.path.join(dest, 'sql')):
        with open(os.path.join(dest, 'sql', f), 'rb') as fh:
            try:
                fh.read().decode('ascii')
            except UnicodeDecodeError:
                fail('SQL 파일에 ASCII 가 아닌 문자가 있다: sql/' + f)
    log('[정상] SQL 파일은 모두 ASCII 이다')


def make_zip(dest, zip_path):
    if os.path.exists(zip_path):
        os.remove(zip_path)
    base = os.path.basename(dest)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for b, dirs, files in os.walk(dest):
            dirs.sort()
            for f in sorted(files):
                full = os.path.join(b, f)
                z.write(full, os.path.join(base, os.path.relpath(full, dest)))
    log('[정상] 압축 파일: ' + os.path.relpath(zip_path, ROOT))


def main():
    ap = argparse.ArgumentParser(description='OCS-LITE 설치 패키지 만들기')
    ap.add_argument('--out', default='dist', help='만들 위치 (기본 dist)')
    ap.add_argument('--no-zip', action='store_true', help='압축 파일을 만들지 않는다')
    ap.add_argument('--skip-tests', action='store_true',
                    help='lite/tests 를 돌리지 않는다(시험 코드가 이 도구를 부를 때만 쓴다)')
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime('%Y%m%d')
    name = 'ocs-lite-install-%s' % stamp
    out_root = args.out if os.path.isabs(args.out) else os.path.join(ROOT, args.out)
    dest = os.path.join(out_root, name)

    print('=== OCS-LITE 설치 패키지 만들기 ===')
    check_sql_list()
    if not args.skip_tests:
        run_tests()
    if git_dirty():
        log('[주의] lite/ 또는 tools/ 에 커밋하지 않은 변경이 있다. 이 패키지의 소스 판 번호는 변경 전 기준이다.')

    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)

    for src, dst in FILES.items():
        copy(src, dest, dst)
    for f in SQL_FILES:
        copy(os.path.join('lite', 'sql', f), dest, os.path.join('sql', f))
    log('[정상] 파일 %d개를 담았다' % (len(FILES) + len(SQL_FILES)))

    check_ascii(dest)
    check_manual_paths(dest)

    with open(os.path.join(dest, 'VERSION'), 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('OCS-LITE 설치 패키지\n빌드 일자: %s\n소스 판: %s\n' % (stamp, git_rev()))
    write_manifest(dest)

    if not args.no_zip:
        make_zip(dest, dest + '.zip')

    print('\n패키지: ' + os.path.relpath(dest, ROOT))
    print('받는 쪽은 푼 뒤 최상위 폴더에서 sha256sum -c MANIFEST.sha256 로 확인한 다음 안내서.md 제3장을 따른다.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
