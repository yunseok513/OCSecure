# -*- coding: utf-8 -*-
"""매뉴얼의 목차를 만든다.

  python tools/make_toc.py            대상 문서의 목차를 다시 만든다
  python tools/make_toc.py --check    목차가 제목과 맞는지만 본다 (다르면 종료 코드 1)

설치 매뉴얼은 tools/build_manual.py 가 만들 때 목차도 함께 넣으므로 여기 대상이 아니다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import toc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = [
    os.path.join('docs', '개발자', '개발자_매뉴얼.md'),
    os.path.join('docs', '유지보수', '유지보수_매뉴얼.md'),
    os.path.join('docs', '저장소', '빌드_및_시험_설명서.md'),
]


def main():
    check = '--check' in sys.argv
    bad = 0
    for rel in DOCS:
        path = os.path.join(ROOT, rel)
        cur = open(path, encoding='utf-8').read()
        new = toc.apply(cur)
        if new != cur:
            if check:
                print('목차가 제목과 다르다: ' + rel)
                bad += 1
            else:
                with open(path, 'w', encoding='utf-8', newline='\n') as fh:
                    fh.write(new)
                print('목차를 만들었다: ' + rel)
    if check:
        if bad:
            print('python tools/make_toc.py 로 다시 만들 것.')
            return 1
        print('목차가 모두 맞는다.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
