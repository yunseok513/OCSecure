# -*- coding: utf-8 -*-
"""설치 패키지 만들기.

외부에 전달할 설치 패키지를 만든다. 패키지에는 설치 매뉴얼과, 매뉴얼이 쓰는
파일만 들어간다. 담을 파일을 아래 목록에 하나하나 적어 두는 방식이므로 목록에
없는 파일(내부 기록, 설계 문서, 조사 도구, 시험 코드 등)은 저장소에 있어도
패키지에 들어가지 않는다. 새 파일을 패키지에 넣으려면 이 목록에 적어야 한다.

  python tools/make_install_package.py
  python tools/make_install_package.py --no-zip
  python tools/make_install_package.py --with-ops-docs   # 관리자·개발자 매뉴얼도 담음

만든 뒤에는 packages 안의 매뉴얼이 언급하는 경로가 실제로 있는지를
tools/check_manual_paths.py 로 대조한다.
"""

import argparse
import datetime
import hashlib
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import to_cp949   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MANUAL_SRC = os.path.join('docs', '80_설치_매뉴얼.md')
MANUAL_DST = '설치_매뉴얼.md'

# 담을 디렉터리(통째로). 이 안의 파일은 모두 설치에 쓰인다.
COPY_DIRS = [
    os.path.join('sql', '01_schema'),
    os.path.join('sql', '02_packages'),
    os.path.join('sql', '03_grants'),
    os.path.join('sql', '08_sample'),
    os.path.join('sql', '09_test'),
    os.path.join('sql', '99_uninstall'),
    os.path.join('java', 'src'),
]

# 담을 파일(하나하나). 04_admin 은 설치에 쓰는 것만 담는다.
COPY_FILES = [
    os.path.join('sql', '04_admin', '400_pwd_iteration_tune.sql'),
    os.path.join('sql', '04_admin', '401_pwd_iteration_dist.sql'),
    os.path.join('sql', '04_admin', '450_bootstrap_domains.sql'),
    os.path.join('sql', '04_admin', '460_appctx_key.sql'),
    os.path.join('sql', '04_admin', '470_keystore_check.sql'),
    os.path.join('sql', '04_admin', '480_connect_app_schema.sql'),
    os.path.join('java', 'pom.xml'),
    os.path.join('java', 'keeper.bat'),
    os.path.join('java', 'keeper.properties.sample'),
    os.path.join('tools', 'verify_manifest.py'),
    os.path.join('tools', 'to_cp949.py'),
]

# 선택으로 담는 문서 (--with-ops-docs). 원본 경로 -> 패키지 안 이름
OPS_DOCS = {
    os.path.join('docs', '60_비밀번호시스템_관리자설명서.md'): '관리자_매뉴얼.md',
    os.path.join('docs', '61_비밀번호시스템_개발자설명서.md'): '개발자_매뉴얼.md',
    os.path.join('docs', '62_오류_대응_매뉴얼.md'): '오류_대응_매뉴얼.md',
}

SKIP_NAMES = {'__pycache__', '.git', 'target', 'build'}


def log(msg):
    print('  ' + msg)


def copy_file(rel_src, dest, rel_dst=None):
    src = os.path.join(ROOT, rel_src)
    if not os.path.isfile(src):
        raise SystemExit('[오류] 담을 파일이 없다: ' + rel_src)
    dst = os.path.join(dest, rel_dst or rel_src)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)


def copy_tree(rel_src, dest):
    src = os.path.join(ROOT, rel_src)
    if not os.path.isdir(src):
        raise SystemExit('[오류] 담을 폴더가 없다: ' + rel_src)
    n = 0
    for base, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_NAMES)
        for f in sorted(files):
            if f.endswith('.pyc'):
                continue
            rel = os.path.relpath(os.path.join(base, f), ROOT)
            copy_file(rel, dest)
            n += 1
    return n


def build_jar(dest):
    """응용 서버용 라이브러리를 미리 컴파일해 담는다. 자바 8 대상."""
    if shutil.which('javac') is None or shutil.which('jar') is None:
        log('[건너뜀] javac 또는 jar 가 없어 라이브러리를 만들지 못했다.')
        return False
    classes = os.path.join(dest, '_classes')
    os.makedirs(classes)
    sources = []
    for base, _d, files in os.walk(os.path.join(ROOT, 'java', 'src', 'main')):
        sources += [os.path.join(base, f) for f in files if f.endswith('.java')]
    cmd = ['javac', '--release', '8', '-encoding', 'UTF-8', '-d', classes] + sorted(sources)
    if subprocess.call(cmd, stderr=subprocess.DEVNULL) != 0:
        log('[실패] 자바 컴파일에 실패하였다.')
        shutil.rmtree(classes)
        return False
    jar_path = os.path.join(dest, 'java', 'ocsecure-client-1.0.0.jar')
    if subprocess.call(['jar', 'cf', jar_path, '-C', classes, '.']) != 0:
        log('[실패] 라이브러리 묶기에 실패하였다.')
        shutil.rmtree(classes)
        return False
    shutil.rmtree(classes)
    log('[정상] 자바 라이브러리를 만들었다 (자바 8 대상)')
    return True


def git_rev():
    try:
        out = subprocess.check_output(['git', '-C', ROOT, 'rev-parse', '--short', 'HEAD'],
                                      stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return 'unknown'


def write_version(dest, stamp, rev):
    with open(os.path.join(dest, 'VERSION'), 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('OCSecure 설치 패키지\n빌드 일자: %s\n소스 판: %s\n' % (stamp, rev))


def write_manifest(dest):
    rows = []
    for base, dirs, files in os.walk(dest):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_NAMES)
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


def main():
    ap = argparse.ArgumentParser(description='설치 패키지 만들기')
    ap.add_argument('--out', default='dist', help='만들 위치 (기본 dist)')
    ap.add_argument('--no-zip', action='store_true', help='압축 파일을 만들지 않는다')
    ap.add_argument('--with-ops-docs', action='store_true',
                    help='관리자·개발자·오류 대응 매뉴얼도 담는다')
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime('%Y%m%d')
    name = 'ocsecure-install-%s' % stamp
    out_root = os.path.join(ROOT, args.out)
    dest = os.path.join(out_root, name)

    print('=== 설치 패키지 만들기 ===')
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)

    # 설치 매뉴얼은 원본에서 만든 결과여야 한다. 어긋나 있으면 중단한다.
    if subprocess.call([sys.executable, '-I', os.path.join(ROOT, 'tools', 'build_manual.py'), '--check']) != 0:
        raise SystemExit('[오류] 설치 매뉴얼이 원본과 다르다. python tools/build_manual.py 를 먼저 실행하십시오.')
    copy_file(MANUAL_SRC, dest, MANUAL_DST)
    count = 1
    for d in COPY_DIRS:
        count += copy_tree(d, dest)
    for f in COPY_FILES:
        copy_file(f, dest)
        count += 1
    if args.with_ops_docs:
        for src, dst in OPS_DOCS.items():
            copy_file(src, dest, dst)
            count += 1
    log('[정상] 파일 %d개를 담았다' % count)

    n_f, _h, probs = to_cp949.convert(
        os.path.join(dest, 'sql'), os.path.join(dest, 'sql_cp949'), False)
    if probs:
        log('[경고] CP949 로 옮기지 못한 파일 %d개가 있다' % len(probs))
    log('[정상] CP949 사본 %d개를 sql_cp949/ 에 담았다' % n_f)

    if not build_jar(dest):
        log('[주의] 미리 컴파일한 jar 없이 만들어졌다. 설치에는 지장이 없으나, 응용 서버에 jar 를 전달해야 하면 JDK 가 있는 장비에서 다시 만드십시오.')

    write_version(dest, stamp, git_rev())
    write_manifest(dest)

    checker = os.path.join(ROOT, 'tools', 'check_manual_paths.py')
    if os.path.exists(checker):
        rc = subprocess.call([sys.executable, '-I', checker, dest])
        if rc != 0:
            raise SystemExit('[오류] 매뉴얼이 언급하는 경로 중 패키지에 없는 것이 있다.')

    if not args.no_zip:
        archive = shutil.make_archive(dest, 'zip', out_root, name)
        log('[정상] 압축 파일을 만들었다 (%.1f MB)' % (os.path.getsize(archive) / 1048576.0))
        print('\n배포 대상: %s' % os.path.relpath(archive, ROOT))
    else:
        print('\n배포 대상: %s' % os.path.relpath(dest, ROOT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
