# -*- coding: utf-8 -*-
"""오라클 스크립트를 CP949(ANSI) 인코딩으로 바꿔 담는다.

저장소의 원본은 UTF-8 이다. 그런데 데이터베이스 문자집합이 KO16MSWIN949 인
곳에서 SQL*Plus 로 원본을 그대로 실행하면, 클라이언트가 파일의 바이트를
CP949 로 해석해 데이터베이스로 보낸다. 한글 한 글자가 UTF-8 에서는 3바이트,
CP949 에서는 2바이트이므로 바이트 수가 어긋나고, 앞 바이트가 뒤따르는 줄바꿈이나
따옴표를 제 짝으로 삼켜 버리는 일이 생긴다. 그러면 주석이 다음 줄을 먹거나
문자열이 닫히지 않아 컴파일이 깨진다.

해결 방법은 두 가지이며, 둘 중 하나만 하면 된다.

  (가) 파일을 CP949 로 바꿔서 실행한다. 이 도구가 하는 일이다.

        python tools/to_cp949.py
        sqlplus OCS_OWNER/...@... @sql_cp949/02_packages/210_pkg_rekey.sql

  (나) 파일은 그대로 두고 클라이언트에 원본이 UTF-8 임을 알린다.

        Windows :  set NLS_LANG=KOREAN_KOREA.AL32UTF8
                   chcp 65001
        Linux   :  export NLS_LANG=KOREAN_KOREA.AL32UTF8

      이러면 SQL*Plus 가 보낸 UTF-8 을 데이터베이스가 KO16MSWIN949 로 옮겨
      담으므로 파일을 건드릴 필요가 없다. 다만 화면 출력도 UTF-8 이 되므로
      콘솔 코드페이지를 함께 바꾸지 않으면 결과가 깨져 보인다.

두 방법을 섞으면 안 된다. CP949 로 바꾼 파일을 NLS_LANG=...AL32UTF8 로 실행하면
같은 문제가 반대 방향으로 생긴다.

사용법
  python tools/to_cp949.py              sql/ 을 읽어 sql_cp949/ 로 쓴다
  python tools/to_cp949.py --check      바꿀 수 없는 글자만 찾아보고 쓰지는 않는다
  python tools/to_cp949.py --src docs --dest docs_cp949
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {'__pycache__', '.git'}


def convert(src_root, dest_root, check_only):
    n_file = n_hangul = 0
    problems = []

    for base, dirs, files in os.walk(src_root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            src = os.path.join(base, name)
            rel = os.path.relpath(src, src_root)
            with open(src, encoding='utf-8') as fh:
                text = fh.read()

            bad = sorted({ch for ch in text if _unmappable(ch)})
            if bad:
                problems.append((rel, bad))
                continue

            n_file += 1
            if any(ord(ch) > 127 for ch in text):
                n_hangul += 1
            if check_only:
                continue

            dst = os.path.join(dest_root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            # 줄바꿈은 원본 그대로 둔다. SQL*Plus 는 둘 다 받아들인다.
            with open(dst, 'w', encoding='cp949', newline='') as fh:
                fh.write(text)

    return n_file, n_hangul, problems


def _unmappable(ch):
    if ord(ch) < 128:
        return False
    try:
        ch.encode('cp949')
        return False
    except UnicodeEncodeError:
        return True


def main():
    ap = argparse.ArgumentParser(description='스크립트를 CP949 로 바꿔 담는다.')
    ap.add_argument('--src', default='sql', help='원본 디렉터리 (기본 sql)')
    ap.add_argument('--dest', default=None, help='결과 디렉터리 (기본 <원본>_cp949)')
    ap.add_argument('--check', action='store_true', help='점검만 하고 쓰지 않는다')
    args = ap.parse_args()

    src_root = args.src if os.path.isabs(args.src) else os.path.join(ROOT, args.src)
    if not os.path.isdir(src_root):
        print('원본 디렉터리가 없다: ' + src_root)
        return 2

    dest = args.dest or (args.src.rstrip('/\\') + '_cp949')
    dest_root = dest if os.path.isabs(dest) else os.path.join(ROOT, dest)

    n_file, n_hangul, problems = convert(src_root, dest_root, args.check)

    for rel, bad in problems:
        print('  [오류] %s: CP949 로 옮길 수 없는 글자 %s'
              % (rel, ' '.join('U+%04X(%s)' % (ord(c), c) for c in bad)))

    if args.check:
        print('점검 파일 %d개 (한글 포함 %d개), 옮길 수 없는 파일 %d개'
              % (n_file, n_hangul, len(problems)))
    else:
        print('%s -> %s : 파일 %d개를 CP949 로 썼다 (한글 포함 %d개), 실패 %d개'
              % (args.src, dest, n_file, n_hangul, len(problems)))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
