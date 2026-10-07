# -*- coding: utf-8 -*-
"""마크다운 문서의 목차를 제목에서 만든다.

문서의 첫 제목(# ...) 바로 아래에 목차를 둔다. 목차는 아래 두 표시 사이에 들어가며, 표시 안의
내용은 이 도구가 만든 것이므로 직접 고치지 않는다. 표시에는 도구 이름을 적지 않는다(설치
매뉴얼처럼 외부에 나가는 문서에서 내부 도구 이름이 보이지 않게 하려는 것이다). 표시가 없으면 첫 제목 아래에 새로 넣는다.

  <!-- 목차 시작 -->
  ...
  <!-- 목차 끝 -->

포함하는 제목은 ## 와 ### 이다. 코드 블록 안의 # 줄은 제목이 아니므로 건너뛴다. 링크는
GitHub 방식의 제목 주소(소문자, 문장 부호 제거, 공백은 하이픈, 같은 제목은 -1, -2)를 쓴다.
링크가 동작하지 않는 곳에서도 번호가 있어 목차로 읽힌다.
"""

import re

START = '<!-- 목차 시작 -->'
END = '<!-- 목차 끝 -->'
START_RE = re.compile(r'<!-- 목차 시작[^>]*-->')
LEVELS = (2, 3)


def _plain(title):
    t = re.sub(r'`([^`]*)`', r'\1', title)
    t = re.sub(r'\*\*([^*]*)\*\*', r'\1', t)
    t = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', t)
    return t.strip()


def _slug(title):
    t = _plain(title).lower()
    t = re.sub(r'[^\w\- ]', '', t)
    return t.replace(' ', '-')


def headings(text):
    """(수준, 제목) 목록. 목차 블록과 코드 블록 안은 건너뛴다."""
    out, in_fence, in_toc = [], False, False
    for line in text.split('\n'):
        if START_RE.search(line):
            in_toc = True
            continue
        if END in line:
            in_toc = False
            continue
        if in_toc:
            continue
        if line.startswith('```'):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r'^(#{1,6}) +(.*\S)\s*$', line)
        if m:
            out.append((len(m.group(1)), m.group(2)))
    return out


def build(text):
    seen, lines = {}, []
    for level, title in headings(text):
        slug = _slug(title)
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        anchor = slug if n == 0 else '%s-%d' % (slug, n)
        if level in LEVELS and title != '목차':
            indent = '  ' * (level - LEVELS[0])
            lines.append('%s- [%s](#%s)' % (indent, _plain(title), anchor))
    return '\n'.join(lines)


def apply(text):
    body = build(text)
    block = '%s\n## 목차\n\n%s\n%s' % (START, body, END)
    m = START_RE.search(text)
    if m:
        a = m.start()
        b = text.index(END, a) + len(END)
        return text[:a] + block + text[b:]
    # 표시가 없으면 첫 제목 줄 바로 아래에 넣는다.
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if re.match(r'^# +\S', line):
            return '\n'.join(lines[:i + 1]) + '\n\n' + block + '\n' + '\n'.join(lines[i + 1:])
    return text
