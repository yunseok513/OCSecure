# -*- coding: utf-8 -*-
"""설치 매뉴얼 만들기.

설치 환경(개발·시험, 운영)과 운영체제(윈도우, RHEL)의 네 조합이 같은 순서와 같은 SQL
절차를 가지므로, 한 원본에서 네 편을 만들어 한 파일에 담는다. 편을 손으로 따로 고치다가
어긋나는 것을 막기 위해서다.

  원본   docs/설치/설치_매뉴얼.tmpl.md
  결과   docs/설치/설치_매뉴얼.md        (직접 고치지 않는다. 원본을 고치고 다시 만든다)

  python tools/build_manual.py           결과를 다시 만든다
  python tools/build_manual.py --check   결과가 원본과 맞는지만 본다 (다르면 종료 코드 1)

원본의 구성   머리(공통) / @@@INSTALL(설치 진행) / @@@VERIFY(설치 후 확인) / @@@REF(참고, 공통)

원본의 표기

  @@win / @@rhel / @@end   해당 운영체제 편에만 들어가는 블록. 블록 밖은 공통이다.
  @@dev / @@ops / @@all    개발·시험 편 또는 운영 편에만 들어가는 블록. @@all 로 끝낸다.
                           운영체제 블록과는 서로 독립이다.
  @@demo [옵션]            연동 확인 프로그램 실행 명령. 운영체제에 맞게 풀어 쓴다.
  {I}  설치 진행 장 번호    {V}  설치 후 확인 장 번호    {R}  참고 사항 장 번호    {S}  요약 장 번호
  편의 장 번호: 개발·시험 윈도우 3·4, 개발·시험 RHEL 5·6, 운영 윈도우 7·8, 운영 RHEL 9·10,
  참고 11, 요약 12. 공통 장(소개, 설치 전 확인, 참고 사항)에서 제{I}.9절 은 네 편의 절을
  함께 가리키므로 제(3·5·7·9).9절 로 풀어 쓴다.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import toc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMPL = os.path.join(ROOT, 'docs', '설치', '설치_매뉴얼.tmpl.md')
OUT = os.path.join(ROOT, 'docs', '설치', '설치_매뉴얼.md')

# (환경, 운영체제, 설치 진행 장, 설치 후 확인 장, 이름)
EDITIONS = [
    ('dev', 'win', 3, 4, '개발·시험 설치 — 윈도우 편'),
    ('dev', 'rhel', 5, 6, '개발·시험 설치 — RHEL 편'),
    ('ops', 'win', 7, 8, '운영 설치 — 윈도우 편'),
    ('ops', 'rhel', 9, 10, '운영 설치 — RHEL 편'),
]
REF_NO = 11
SUMMARY_NO = 12
I_ALL = '·'.join(str(e[2]) for e in EDITIONS)
V_ALL = '·'.join(str(e[3]) for e in EDITIONS)
URL = '"jdbc:oracle:thin:@<호스트>:<포트>/<서비스명>" <응용계정> - -'


def demo(os_key, opts):
    tail = (' ' + opts) if opts else ''
    if os_key == 'win':
        return ['java -cp out;ojdbc8.jar ocsecure.client.OcsConnectDemo ^',
                '     ' + URL + tail]
    return ['java -cp out:ojdbc8.jar ocsecure.client.OcsConnectDemo \\',
            '     ' + URL + tail]


def render_edition(text, env, os_key, I, V):
    out, cur, cur_env, in_fence = [], None, None, False
    for line in text.split('\n'):
        t = line.strip()
        if t in ('@@win', '@@rhel'):
            cur = t[2:]
            continue
        if t == '@@end':
            cur = None
            continue
        if t in ('@@dev', '@@ops'):
            cur_env = t[2:]
            continue
        if t == '@@all':
            cur_env = None
            continue
        if cur is not None and cur != os_key:
            continue
        if cur_env is not None and cur_env != env:
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
    return fill_numbers(s.replace('{I}', str(I)).replace('{V}', str(V)))


def fill_numbers(s):
    return s.replace('{R}', str(REF_NO)).replace('{S}', str(SUMMARY_NO))


def render_shared(text):
    """공통 장의 절 참조를 네 편을 함께 가리키는 모양으로 푼다."""
    def ref(m):
        all_no = I_ALL if m.group(1) == 'I' else V_ALL
        return '제(%s)%s절' % (all_no, m.group(2))
    text = re.sub(r'제\{([IV])\}((?:\.\d+)+)절', ref, text)
    text = re.sub(r'제\{([IV])\}장',
                  lambda m: '제(%s)장' % (I_ALL if m.group(1) == 'I' else V_ALL), text)

    def bare(m):
        all_no = I_ALL if m.group(1) == 'I' else V_ALL
        return '(%s)%s' % (all_no, m.group(2))
    text = re.sub(r'\{([IV])\}((?:\.\d+)+)', bare, text)
    return fill_numbers(text)


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
    for env, key, I, V, name in EDITIONS:
        parts.append('## %d. %s — 설치 진행\n\n%s'
                     % (I, name, render_edition(install, env, key, I, V).strip('\n') + '\n'))
        parts.append('## %d. %s — 설치 후 확인\n\n%s'
                     % (V, name, render_edition(verify, env, key, I, V).strip('\n') + '\n'))
    parts.append(render_shared(ref).strip('\n') + '\n')
    return toc.apply('\n'.join(parts))


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
