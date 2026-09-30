# -*- coding: utf-8 -*-
"""폐쇄망 반입 꾸러미 만들기.

개방망에서 한 번 실행하여 꾸러미를 만들고, 그것을 폐쇄망으로 옮긴다.

  python tools/make_offline_bundle.py
  python tools/make_offline_bundle.py --with-wheels --wheel-platform win_amd64

꾸러미에는 미리 컴파일한 자바 라이브러리와 원본, 오라클 스크립트, 파이썬 도구,
고정 시험 벡터, 설명서, 그리고 모든 파일의 해시 목록이 들어간다. 해시 목록을
두는 이유는 반입 심사에서 파일 목록과 무결성 증빙을 요구하는 경우가 흔하기
때문이며, 옮기는 도중 파일이 손상되지 않았는지 확인하는 데도 쓴다.

자바에는 외부 의존성이 없다. 폐쇄망에 JDK 만 있으면 원본에서 다시 빌드할 수
있고, 그조차 필요 없으면 들어 있는 라이브러리를 그대로 쓰면 된다. Maven 은
필요하지 않다.

파이썬 쪽에서 외부 패키지를 쓰는 것은 참조 구현 하나뿐이다. 나머지 도구는
표준 라이브러리만 쓰므로 그대로 돌아간다. 참조 구현까지 폐쇄망에서 돌려야
한다면 --with-wheels 로 설치 파일을 함께 담는다. 대상 환경의 운영체제와 파이썬
판에 맞는 것을 받아야 하므로 --wheel-platform 과 --wheel-python 을 확인할 것.
"""

import argparse
import datetime
import hashlib
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 꾸러미에 담을 것. 디렉터리는 통째로 옮긴다.
COPY_DIRS = ['sql', 'docs', 'tests', 'tools', os.path.join('java', 'src')]
COPY_FILES = ['README.md', 'requirements.txt', os.path.join('java', 'pom.xml')]
SKIP_DIRS = {'__pycache__', '.git', 'target', 'build'}


def log(msg):
    print('  ' + msg)


def build_jar(dest_dir):
    """자바 라이브러리를 미리 컴파일해 담는다. 폐쇄망에 JDK 가 없어도 쓸 수 있다."""
    if shutil.which('javac') is None or shutil.which('jar') is None:
        log('[건너뜀] javac 또는 jar 가 없어 라이브러리를 미리 만들지 못한다.')
        log('         폐쇄망에서 원본을 직접 컴파일해야 한다.')
        return None

    classes = os.path.join(dest_dir, '_classes')
    os.makedirs(classes)
    sources = []
    for base, _d, files in os.walk(os.path.join(ROOT, 'java', 'src', 'main')):
        sources += [os.path.join(base, f) for f in files if f.endswith('.java')]

    # 대상 환경의 자바가 낮을 수 있으므로 8 을 대상으로 맞춘다.
    cmd = ['javac', '--release', '8', '-encoding', 'UTF-8', '-d', classes] + sorted(sources)
    if subprocess.call(cmd, stderr=subprocess.DEVNULL) != 0:
        log('[실패] 자바 컴파일에 실패하였다.')
        return None

    jar_path = os.path.join(dest_dir, 'java', 'ocsecure-client-1.0.0.jar')
    os.makedirs(os.path.dirname(jar_path), exist_ok=True)
    if subprocess.call(['jar', 'cf', jar_path, '-C', classes, '.']) != 0:
        log('[실패] 라이브러리 묶기에 실패하였다.')
        return None

    shutil.rmtree(classes)
    log('[정상] 자바 라이브러리를 만들었다 (자바 8 대상)')
    return jar_path


def fetch_wheels(dest_dir, platform, py_version):
    """참조 구현이 쓰는 패키지의 설치 파일을 내려받아 담는다."""
    wheels = os.path.join(dest_dir, 'wheels')
    os.makedirs(wheels, exist_ok=True)
    cmd = [sys.executable, '-m', 'pip', 'download',
           '-r', os.path.join(ROOT, 'requirements.txt'),
           '-d', wheels, '--only-binary=:all:']
    if platform:
        cmd += ['--platform', platform]
    if py_version:
        cmd += ['--python-version', py_version]

    if subprocess.call(cmd, stdout=subprocess.DEVNULL) != 0:
        log('[실패] 설치 파일을 내려받지 못하였다. 대상 환경과 판 번호를 확인할 것.')
        return False
    got = sorted(os.listdir(wheels))
    log('[정상] 설치 파일 %d개를 담았다' % len(got))
    for g in got:
        log('       ' + g)
    return True


def copy_tree(src, dst):
    for base, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel = os.path.relpath(base, ROOT)
        target = os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for f in files:
            if f.endswith('.pyc'):
                continue
            shutil.copy2(os.path.join(base, f), os.path.join(target, f))


def write_manifest(dest_dir):
    """모든 파일의 해시 목록. 반입 심사 증빙과 손상 확인에 쓴다."""
    rows = []
    for base, dirs, files in os.walk(dest_dir):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            full = os.path.join(base, f)
            rel = os.path.relpath(full, dest_dir).replace(os.sep, '/')
            if rel == 'MANIFEST.sha256':
                continue
            with open(full, 'rb') as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            rows.append('%s  %s' % (digest, rel))

    path = os.path.join(dest_dir, 'MANIFEST.sha256')
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(rows) + '\n')
    log('[정상] 파일 %d개의 해시 목록을 만들었다' % len(rows))
    return len(rows)


def write_readme(dest_dir, made_jar, made_wheels):
    text = '''# OCSecure 폐쇄망 반입 꾸러미

생성 일시: %s

## 들어 있는 것

`sql/` 은 오라클 설치와 관리와 시험 스크립트입니다. 설치 절차는 `sql/00_install.sql`
에 있습니다.

`java/ocsecure-client-1.0.0.jar` 는 미리 컴파일한 자바 연동 라이브러리입니다.
%s외부 의존성이 없으므로 업무 프로젝트의 라이브러리 경로에 두고 클래스패스에
추가하면 그대로 씁니다.

`java/src/` 는 그 원본입니다. 폐쇄망에서 직접 빌드하려면 JDK 만 있으면 됩니다.
Maven 은 필요하지 않습니다.

`tools/` 는 조사와 점검 도구입니다. `legacy_pwd_probe.py` 는 기존 비밀번호
저장 방식을 알아내는 도구로, 대상 자료가 폐쇄망 안에 있으므로 여기서 돌려야
합니다. 이 도구와 `lint_plsql.py` 와 `run_checks.py` 는 표준 라이브러리만 쓰므로
파이썬만 있으면 바로 돌아갑니다.

`tests/vectors/` 는 고정 시험 벡터입니다. 세 구현이 같은 값을 내는지 대조하는
기준이며, 여기서 다시 만들 필요가 없습니다.

`docs/` 는 설명서입니다. 빌드와 시험은 `docs/70` 을 보십시오.

`MANIFEST.sha256` 은 모든 파일의 해시 목록입니다. 반입 심사 증빙과, 옮기는
도중 손상되지 않았는지 확인하는 데 씁니다.

%s
## 옮긴 뒤 확인

파일이 온전한지 먼저 확인합니다.

```
python tools/verify_manifest.py
```

이어서 점검을 돌립니다. 윈도우에서는 `tools\\\\run_checks.bat` 을 씁니다.

```
python tools/run_checks.py
```

`cryptography` 패키지가 없으면 참조 구현 시험과 벡터 대조는 건너뛰고 나머지가
수행됩니다. 그것으로 충분합니다. 벡터는 개방망에서 이미 검증된 것을 그대로
가져온 것이기 때문입니다.

JDK 가 있으면 자바 항목까지 돌아가며, 여기서 통과하면 반입한 라이브러리가
폐쇄망 환경에서도 같은 값을 낸다는 것이 확인됩니다.

## 참조 구현까지 돌려야 한다면

%s'''
    jar_note = ('자바 8 을 대상으로 컴파일하였습니다. '
                if made_jar else
                '**주의: 이 꾸러미에는 미리 컴파일한 라이브러리가 없습니다. '
                '폐쇄망에서 원본을 직접 컴파일해야 합니다.** ')

    wheel_block = ('`wheels/` 는 참조 구현이 쓰는 파이썬 패키지의 설치 파일입니다.\n'
                   if made_wheels else '')

    wheel_how = ('''설치 파일을 함께 담았습니다.

```
pip install --no-index --find-links wheels -r requirements.txt
```

대상 환경의 운영체제와 파이썬 판에 맞지 않으면 설치되지 않습니다. 그때는
개방망에서 맞는 것을 다시 받아 오셔야 합니다.
''' if made_wheels else '''이 꾸러미에는 설치 파일이 들어 있지 않습니다. 참조 구현은
암호 연산에 `cryptography` 패키지를 쓰므로, 필요하다면 개방망에서 다음과 같이
받아 함께 옮기십시오. 대상 환경에 맞는 것을 받아야 합니다.

```
python tools/make_offline_bundle.py --with-wheels \\\\
       --wheel-platform win_amd64 --wheel-python 311
```

참조 구현은 개방망에 두고 결과인 시험 벡터만 옮기는 편이 대개 낫습니다.
폐쇄망에서 벡터를 다시 만들 일은 참조 구현 자체를 고칠 때뿐이고, 그런 작업은
개방망에서 하는 것이 맞기 때문입니다.
''')

    with open(os.path.join(dest_dir, 'README_OFFLINE.md'), 'w',
              encoding='utf-8', newline='\n') as fh:
        fh.write(text % (
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
            jar_note, wheel_block, wheel_how))


def main():
    ap = argparse.ArgumentParser(description='폐쇄망 반입 꾸러미 만들기')
    ap.add_argument('--out', default='dist', help='꾸러미를 만들 위치 (기본 dist)')
    ap.add_argument('--with-wheels', action='store_true',
                    help='참조 구현이 쓰는 파이썬 패키지 설치 파일을 함께 담는다')
    ap.add_argument('--wheel-platform', default=None,
                    help='설치 파일의 대상 환경. 예) win_amd64, manylinux2014_x86_64')
    ap.add_argument('--wheel-python', default=None,
                    help='설치 파일의 대상 파이썬 판. 예) 311')
    ap.add_argument('--no-zip', action='store_true', help='압축 파일을 만들지 않는다')
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime('%Y%m%d')
    name = 'ocsecure-offline-%s' % stamp
    out_root = os.path.join(ROOT, args.out)
    dest = os.path.join(out_root, name)

    print('=== 폐쇄망 반입 꾸러미 만들기 ===')
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)

    for d in COPY_DIRS:
        copy_tree(os.path.join(ROOT, d), dest)
    for f in COPY_FILES:
        target = os.path.join(dest, f)
        os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
        shutil.copy2(os.path.join(ROOT, f), target)
    log('[정상] 원본과 문서와 스크립트를 담았다')

    made_jar = build_jar(dest) is not None

    made_wheels = False
    if args.with_wheels:
        made_wheels = fetch_wheels(dest, args.wheel_platform, args.wheel_python)

    write_readme(dest, made_jar, made_wheels)
    write_manifest(dest)

    if not args.no_zip:
        archive = shutil.make_archive(dest, 'zip', out_root, name)
        size = os.path.getsize(archive) / 1024.0 / 1024.0
        log('[정상] 압축 파일을 만들었다 (%.1f MB)' % size)
        print('')
        print('반입 대상: %s' % os.path.relpath(archive, ROOT))
    else:
        print('')
        print('반입 대상: %s' % os.path.relpath(dest, ROOT))

    print('반입 전에 MANIFEST.sha256 을 심사 자료로 함께 제출할 것.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
