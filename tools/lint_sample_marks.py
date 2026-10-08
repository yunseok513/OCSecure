#!/usr/bin/env python3
"""예시 객체의 표시(COMMENT 'OCSecure sample')가 뒤에서 덮어써지지 않는지 본다.

890_drop_samples.sql 과 개통 판정은 표 설명이 정확히 'OCSecure sample' 인 것만 예시로 본다.
같은 표에 나중에 다른 표 설명을 달면 표시가 사라져 정리 스크립트가 그 표를 건너뛴다.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARK = 'OCSecure sample'
PAT = re.compile(r"COMMENT\s+ON\s+TABLE\s+(\w+)\s+IS\s+'((?:[^']|'')*)'", re.IGNORECASE)


def main():
    bad = 0
    d = os.path.join(ROOT, 'sql', '08_sample')
    for name in sorted(os.listdir(d)):
        if not name.endswith('.sql'):
            continue
        text = open(os.path.join(d, name), encoding='utf-8').read()
        last = {}
        marked = set()
        for m in PAT.finditer(text):
            tbl, val = m.group(1).upper(), m.group(2)
            last[tbl] = val
            if val == MARK:
                marked.add(tbl)
        for tbl in sorted(marked):
            if last[tbl] != MARK:
                bad += 1
                print('  [오류] %s: %s 의 표시가 뒤의 표 설명으로 덮어써진다' % (name, tbl))
    if bad == 0:
        print('  [정상] 예시 표시가 덮어써지지 않는다')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
