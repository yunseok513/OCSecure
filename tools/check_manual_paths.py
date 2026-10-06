# -*- coding: utf-8 -*-
"""설치 매뉴얼이 언급하는 파일 경로가 패키지 안에 실제로 있는지 대조한다.

  python tools/check_manual_paths.py <패키지 폴더>
  python tools/check_manual_paths.py            (저장소의 docs/80 을 저장소 기준으로)

매뉴얼 본문에서 sql/ sql_cp949/ java/ tools/ 로 시작하는 경로를 찾아 존재 여부를
본다. 매뉴얼이 담지 않는 문서(docs/, internal/)를 가리키는 문구도 찾아낸다.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH_RE = re.compile(r'(?<![\w.])((?:sql_cp949|sql|java|tools)[/\\][\w./\\\-]*[\w])')
# 설치하는 사람이 만들거나 설치 중에 생기는 것. 패키지에는 없어도 된다.
GENERATED = {'java/out', 'java/log', 'java/log/keeper.log', 'java/keeper.properties',
             'java/ojdbc8.jar', 'java/srcs.txt'}
BAD_RE = re.compile(r'(docs[/\\]|internal[/\\]|시행착오|진행현황|설계결정기록)')


def main():
    if len(sys.argv) > 1:
        base = sys.argv[1]
        manual = os.path.join(base, '설치_매뉴얼.md')
    else:
        base = ROOT
        manual = os.path.join(ROOT, 'docs', '80_설치_매뉴얼.md')
    if not os.path.exists(manual):
        print('매뉴얼을 찾을 수 없다: ' + manual)
        return 2

    text = open(manual, encoding='utf-8').read()
    missing, seen = [], set()
    for m in PATH_RE.finditer(text):
        p = m.group(1).replace('\\', '/').rstrip('./')
        if p in seen:
            continue
        seen.add(p)
        if p in GENERATED:
            continue
        if len(sys.argv) <= 1 and p.endswith('.jar'):
            continue
        if not os.path.exists(os.path.join(base, p.replace('/', os.sep))):
            missing.append(p)

    bad = sorted({m.group(1) for m in BAD_RE.finditer(text)})

    print('=== 매뉴얼 경로 대조 ===')
    print('  경로 %d개 확인' % len(seen))
    for p in missing:
        print('  [없음] ' + p)
    for b in bad:
        print('  [패키지에 없는 문서를 가리킴] ' + b)
    if missing or bad:
        return 1
    print('  모두 있다')
    return 0


if __name__ == '__main__':
    sys.exit(main())
