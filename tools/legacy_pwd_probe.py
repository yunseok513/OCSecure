# -*- coding: utf-8 -*-
"""기존 비밀번호 저장 방식 식별기.

평문과 그 평문으로 만들어진 저장값 한 쌍을 알고 있을 때, 흔히 쓰이는 구성들을
차례로 재현해 보고 일치하는 것을 찾아낸다. 저장 방식을 확정하는 유일한 방법이
이 대조이며, 나머지는 모두 추정에 그친다.

쌍을 얻는 방법은 시험계에 계정을 하나 만들고 비밀번호를 정해 등록한 뒤, 그
계정의 저장값을 조회하는 것이다. 운영계 사용자의 비밀번호로 시도하지 말 것.

  python3 tools/legacy_pwd_probe.py --plain 'Test1234!' --stored '<저장값>'
  python3 tools/legacy_pwd_probe.py --plain 'Test1234!' --stored '<저장값>' --id 'testuser'

아이디를 함께 넣으면 아이디를 섞는 구성까지 시도한다. 국내 시스템에서는 솔트를
따로 두지 않고 아이디를 솔트처럼 쓰는 구성이 드물지 않으므로, 아이디는 되도록
함께 넣는 편이 낫다.

한계를 분명히 해 둔다. 여기서 시도하는 것은 흔한 구성뿐이다. 일치하는 것이
나오면 그 방식이 맞다고 보아도 되지만, 나오지 않았다고 해서 특별한 방식이라는
뜻은 아니다. 그때는 소스 코드를 확인하는 수밖에 없다.
"""

import argparse
import base64
import binascii
import hashlib
import re
import sys

# 국내 구축 시스템에서는 문자집합이 갈리는 경우가 있다. 한글이 섞인 비밀번호에서
# 결과가 달라지므로 둘 다 시도한다.
CHARSETS = ('utf-8', 'euc-kr')
ALGOS = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')


def encodings_of(digest):
    """같은 해시값이 어떤 표기로 저장되어 있을 수 있는지."""
    return {
        '16진 소문자': digest.hex(),
        '16진 대문자': digest.hex().upper(),
        'Base64': base64.b64encode(digest).decode('ascii'),
        'Base64(패딩 없음)': base64.b64encode(digest).decode('ascii').rstrip('='),
        'Base64 URL': base64.urlsafe_b64encode(digest).decode('ascii'),
    }


def layouts_of(pwd, uid):
    """평문을 어떤 순서로 이어 붙였을 수 있는지."""
    out = [('비밀번호만', pwd)]
    if uid:
        out.append(('아이디 + 비밀번호', uid + pwd))
        out.append(('비밀번호 + 아이디', pwd + uid))
        out.append(('아이디 + 비밀번호 + 아이디', uid + pwd + uid))
    return out


def normalize(stored):
    """저장값 문자열을 비교하기 좋게 다듬는다."""
    return stored.strip()


def probe(plain, stored, uid):
    stored = normalize(stored)
    hits = []

    # 평문 저장은 드물지 않고, 발견되면 가장 시급한 사안이므로 먼저 본다.
    if stored == plain:
        return ['평문 저장 (암호화되어 있지 않다)']
    for cs in CHARSETS:
        try:
            if stored == base64.b64encode(plain.encode(cs)).decode('ascii'):
                return ['평문을 Base64 로 표기만 한 것 (문자집합 %s). '
                        '암호화가 아니며 누구나 되돌릴 수 있다.' % cs]
            if stored.lower() == plain.encode(cs).hex():
                return ['평문을 16진으로 표기만 한 것 (문자집합 %s). '
                        '암호화가 아니며 누구나 되돌릴 수 있다.' % cs]
        except UnicodeEncodeError:
            continue

    for cs in CHARSETS:
        for layout_name, text in layouts_of(plain, uid):
            try:
                raw = text.encode(cs)
            except UnicodeEncodeError:
                continue

            for algo in ALGOS:
                d1 = hashlib.new(algo, raw).digest()

                # 한 번 해싱
                for enc_name, value in encodings_of(d1).items():
                    if value == stored:
                        hits.append('%s / %s / %s / 문자집합 %s'
                                    % (algo.upper(), layout_name, enc_name, cs))

                # 두 번 해싱. 같은 알고리즘을 두 번 거는 구성이 드물지 않다.
                d2 = hashlib.new(algo, d1).digest()
                for enc_name, value in encodings_of(d2).items():
                    if value == stored:
                        hits.append('%s 두 번 / %s / %s / 문자집합 %s'
                                    % (algo.upper(), layout_name, enc_name, cs))

                # 16진 문자열을 다시 해싱하는 구성
                d3 = hashlib.new(algo, d1.hex().encode('ascii')).digest()
                for enc_name, value in encodings_of(d3).items():
                    if value == stored:
                        hits.append('%s 두 번(16진 문자열 경유) / %s / %s / 문자집합 %s'
                                    % (algo.upper(), layout_name, enc_name, cs))

    return hits


def describe_shape(stored):
    """일치하는 것이 없을 때, 저장값의 생김새로 범위를 좁힌다."""
    s = normalize(stored)
    notes = []
    n = len(s)

    if s.startswith('$2a$') or s.startswith('$2b$') or s.startswith('$2y$'):
        notes.append('bcrypt 형식으로 보인다. 이 도구로는 재현하지 않으며, '
                     'bcrypt 검증 라이브러리로 확인해야 한다.')
    if s.startswith('{'):
        notes.append('중괄호로 시작한다. 스프링 시큐리티의 위임 방식처럼 '
                     '접두사로 알고리즘을 표시하는 형식일 수 있다. '
                     '중괄호 안의 이름이 곧 답이다.')
    if re.fullmatch(r'[0-9a-fA-F]+', s):
        notes.append('16진 문자열이며 길이 %d 이므로 %d바이트다. '
                     '32는 MD5, 40은 SHA-1, 64는 SHA-256, 128은 SHA-512 의 길이다.'
                     % (n, n // 2))
    elif re.fullmatch(r'[A-Za-z0-9+/]+=*', s):
        try:
            raw = base64.b64decode(s + '=' * (-len(s) % 4))
            notes.append('Base64 로 보이며 풀면 %d바이트다. '
                         '16은 MD5, 20은 SHA-1, 32는 SHA-256, 64는 SHA-512 의 길이다.'
                         % len(raw))
        except binascii.Error:
            pass
    if not notes:
        notes.append('알려진 형식으로 보이지 않는다. 평문이거나 양방향 암호화일 수 있다.')

    notes.append('길이 %d' % n)
    return notes


def main():
    ap = argparse.ArgumentParser(description='기존 비밀번호 저장 방식 식별기')
    ap.add_argument('--plain', required=True, help='알고 있는 평문 비밀번호')
    ap.add_argument('--stored', required=True, help='그 평문으로 저장된 값')
    ap.add_argument('--id', dest='uid', default=None, help='해당 계정의 아이디(선택)')
    args = ap.parse_args()

    print('=== 기존 비밀번호 저장 방식 식별 ===')
    hits = probe(args.plain, args.stored, args.uid)

    if hits:
        print('일치하는 구성을 찾았다.')
        for h in hits:
            print('  [일치] ' + h)
        if len(hits) > 1:
            print('둘 이상 나온 것은 표기만 다르고 실질이 같은 경우가 대부분이다.')
        if any('평문' in h for h in hits):
            print('')
            print('이것은 이행 문제가 아니라 사고에 가깝다. 개인정보 보호 법령은')
            print('비밀번호를 복호화되지 않는 일방향 암호화로 저장하도록 요구하는 것으로')
            print('알려져 있다. 보안 담당자에게 즉시 보고하고, 이행을 서두르되')
            print('평문이 백업 매체와 로그에 남아 있지 않은지도 함께 확인해야 한다.')
            print('다만 이행 자체는 오히려 쉽다. 평문을 알고 있으므로 일괄 변환이 된다.')
        else:
            print('이 구성을 legacyVerify 에 그대로 옮기면 된다.')
        return 0

    print('흔한 구성 중에는 일치하는 것이 없다.')
    print('저장값의 생김새로 보아 다음과 같다.')
    for note in describe_shape(args.stored):
        print('  ' + note)
    print('다음 단계는 소스 코드 확인이다. 로그인 처리 코드에서 비밀번호를 다루는')
    print('지점을 찾아 어떤 함수를 거치는지 따라가야 한다.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
