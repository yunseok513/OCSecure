# -*- coding: utf-8 -*-
"""윈도우 배치 파일 정적 점검.

괄호 블록(`if ... (` 로 열고 줄 맨 앞의 `)` 로 닫는 구간) 안의 줄에 이스케이프하지 않은
닫는 괄호가 있으면 명령 프롬프트가 거기서 블록이 끝난 것으로 읽어 `or was unexpected at
this time.` 같은 오류로 멈춘다. 따옴표 안의 괄호와 `rem` 줄은 문제가 없다.

  python tools/lint_bat.py
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check(path):
    errs = []
    depth = 0
    with open(path, encoding='utf-8', newline='') as fh:
        lines = fh.read().splitlines()
    for no, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.lower().startswith('rem ') or line.lower() == 'rem':
            continue
        if depth > 0 and line.startswith(')'):
            depth -= 1
            continue
        if depth > 0:
            body = re.sub(r'"[^"]*"', '', line)       # 따옴표 안은 제외
            body = body.replace('^)', '').replace('^(', '')
            if ')' in body:
                errs.append('%s:%d: 괄호 블록 안의 줄에 닫는 괄호가 있다. ^) 로 이스케이프하거나 '
                            '괄호를 쓰지 말 것: %s' % (os.path.basename(path), no, line[:80]))
        if line.endswith('('):
            depth += 1
    if depth != 0:
        errs.append('%s: 괄호 블록이 닫히지 않았다' % os.path.basename(path))
    return errs


def main():
    files = sorted(glob.glob(os.path.join(ROOT, 'java', '*.bat')))
    errs = []
    for f in files:
        errs.extend(check(f))
    for e in errs:
        print('  [오류] ' + e)
    print('점검 파일 %d개, 오류 %d건' % (len(files), len(errs)))
    return 1 if errs else 0


if __name__ == '__main__':
    sys.exit(main())
