# -*- coding: utf-8 -*-
"""반입 꾸러미의 파일이 온전한지 확인한다.

폐쇄망으로 옮긴 직후에 돌린다. 옮기는 도중 파일이 빠지거나 손상되지 않았는지,
그리고 심사에 제출한 목록과 실제 내용이 같은지를 대조한다.

  python tools/verify_manifest.py

표준 라이브러리만 쓰므로 폐쇄망에서도 그대로 돌아간다.
"""

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, 'MANIFEST.sha256')


def main():
    if not os.path.exists(MANIFEST):
        print('MANIFEST.sha256 을 찾을 수 없다.')
        print('이 도구는 반입 꾸러미 안에서만 쓴다. 꾸러미는 다음으로 만든다.')
        print('  python tools/make_offline_bundle.py')
        return 2

    listed = {}
    with open(MANIFEST, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split('  ', 1)
            listed[rel] = digest

    print('=== 반입 꾸러미 무결성 확인 ===')
    missing, changed, ok = [], [], 0

    for rel, want in sorted(listed.items()):
        full = os.path.join(ROOT, rel.replace('/', os.sep))
        if not os.path.exists(full):
            missing.append(rel)
            continue
        with open(full, 'rb') as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        if got != want:
            changed.append(rel)
        else:
            ok += 1

    # 목록에 없는 파일도 알려 준다. 반입 심사에서 문제가 되는 쪽이다.
    extra = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in ('__pycache__', '.git')]
        for f in files:
            rel = os.path.relpath(os.path.join(base, f), ROOT).replace(os.sep, '/')
            if rel != 'MANIFEST.sha256' and rel not in listed:
                extra.append(rel)

    print('  일치 %d개' % ok)
    for rel in missing:
        print('  [없음] ' + rel)
    for rel in changed:
        print('  [손상] ' + rel)
    for rel in sorted(extra):
        print('  [목록에 없는 파일] ' + rel)

    if missing or changed:
        print('=== 확인 실패. 꾸러미를 다시 옮길 것. ===')
        return 1
    if extra:
        print('=== 파일은 온전하나 목록에 없는 것이 있다. 심사 자료와 대조할 것. ===')
        return 0
    print('=== 모든 파일이 온전하다 ===')
    return 0


if __name__ == '__main__':
    sys.exit(main())
