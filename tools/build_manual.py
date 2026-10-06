# -*- coding: utf-8 -*-
"""설치 매뉴얼 만들기.

윈도우 편과 RHEL 편이 같은 순서와 같은 SQL 절차를 가지므로, 한 원본에서 두 편을
만들어 한 파일에 담는다. 두 편을 손으로 따로 고치다가 어긋나는 것을 막기 위해서다.

  원본   docs/80_설치_매뉴얼.tmpl.md
  결과   docs/80_설치_매뉴얼.md        (직접 고치지 않는다. 원본을 고치고 다시 만든다)

  python tools/build_manual.py           결과를 다시 만든다
  python tools/build_manual.py --check   결과가 원본과 맞는지만 본다 (다르면 종료 코드 1)

원본의 표기

  @@win / @@rhel / @@end   해당 운영체제 편에만 들어가는 블록. 블록 밖은 공통이다.
  @@demo [옵션]            연동 확인 프로그램 실행 명령. 운영체제에 맞게 풀어 쓴다.
  {I}  설치 진행 장 번호(윈도우 3, RHEL 5)    {V}  설치 후 확인 장 번호(윈도우 4, RHEL 6)
  공통 장(소개, 설치 전 확인, 참고 사항)에서 제{I}.9절 은 두 편의 절을 함께 가리킨다.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMPL = os.path.join(ROOT, 'docs', '80_설치_매뉴얼.tmpl.md')
OUT = os.path.join(ROOT, 'docs', '80_설치_매뉴얼.md')

OSES = [
    ('win', 'win', 3, 4, '윈도우 편'),
    ('rhel', 'rhel', 5, 6, 'RHEL 편'),
]
URL = '"jdbc:oracle:thin:@<호스트>:<포트>/<서비스명>" OCS_APP - -'


def demo(os_key, opts):
    tail = (' ' + opts) if opts else ''
    if os_key == 'win':
        return ['java -cp out;ojdbc8.jar ocsecure.client.OcsConnectDemo ^',
                '     ' + URL + tail]
    return ['java -cp out:ojdbc8.jar ocsecure.client.OcsConnectDemo \\',
            '     ' + URL + tail]


def render_os(text, os_key, I, V):
    out, cur, in_fence = [], None, False
    for line in text.split('\n'):
        t = line.strip()
        if t in ('@@win', '@@rhel'):
            cur = t[2:]
            continue
        if t == '@@end':
            cur = None
            continue
        if cur is not None and cur != os_key:
            continue
        if t.startswith('@@demo'):
            lines = demo(os_key, t[len('@@demo'):].strip())
            if in_fence:
                out.extend(lines)
            else:
                out.extend(['```'] + lines + ['```'])
            continue
        if line.startswith('```'):
            in_fence = not in_fence
        out.append(line)
    s = '\n'.join(out)
    return s.replace('{I}', str(I)).replace('{V}', str(V))


def render_shared(text):
    def ref(m):
        k = m.group(1)
        sub = m.group(2)
        w = 3 if k == 'I' else 4
        r = 5 if k == 'I' else 6
        return '제%d%s절 (RHEL 편 제%d%s절)' % (w, sub, r, sub)
    text = re.sub(r'제\{([IV])\}((?:\.\d+)+)절', ref, text)
    def bare(m):
        k = m.group(1)
        sub = m.group(2)
        w = 3 if k == 'I' else 4
        r = 5 if k == 'I' else 6
        return '%d%s (RHEL %d%s)' % (w, sub, r, sub)
    return re.sub(r'\{([IV])\}((?:\.\d+)+)', bare, text)


def build():
    src = open(TMPL, encoding='utf-8').read()
    i = src.index('@@@INSTALL\n')
    v = src.index('@@@VERIFY\n')
    r = src.index('@@@REF\n')
    shared_head = src[:i]
    install = src[i + len('@@@INSTALL\n'):v]
    verify = src[v + len('@@@VERIFY\n'):r]
    ref = src[r + len('@@@REF\n'):]

    parts = [render_shared(shared_head).rstrip('\n') + '\n']
    for key, _k, I, V, name in OSES:
        parts.append('## %d. %s — 설치 진행\n\n%s' % (I, name, render_os(install, key, I, V).strip('\n') + '\n'))
        parts.append('## %d. %s — 설치 후 확인\n\n%s' % (V, name, render_os(verify, key, I, V).strip('\n') + '\n'))
    parts.append(render_shared(ref).strip('\n') + '\n')
    return '\n'.join(parts)


def main():
    out = build()
    if '--check' in sys.argv:
        cur = open(OUT, encoding='utf-8').read() if os.path.exists(OUT) else ''
        if cur != out:
            print('설치 매뉴얼이 원본과 다르다. python tools/build_manual.py 로 다시 만들 것.')
            return 1
        print('설치 매뉴얼이 원본과 맞는다.')
        return 0
    with open(OUT, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(out)
    print('만들었다: %s (%d줄)' % (os.path.relpath(OUT, ROOT), out.count('\n')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
