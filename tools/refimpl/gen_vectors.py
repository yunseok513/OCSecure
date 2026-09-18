# -*- coding: utf-8 -*-
"""고정 시험 벡터(Known Answer Test) 생성기.

참조 구현이 만들어 낸 값을 JSON 과 SQL 두 형태로 떨어뜨린다. PL/SQL 자체 시험은
SQL 쪽을 읽어 자신의 계산 결과와 대조하고, 응용 계층(자바 등) 연동 시험은 JSON 을
사용한다. 두 구현이 같은 벡터를 통과하면 바이트 단위로 호환된다고 볼 수 있다.

벡터는 결정적이어야 하므로 키와 초기화 벡터와 솔트를 모두 고정한다. 여기 박혀
있는 값은 시험 전용이며 어떤 환경에서도 실제 키로 사용해서는 안 된다.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ocsecure_ref as R  # noqa: E402

# --- 고정 입력 (시험 전용) --------------------------------------------------
KEK = bytes(range(0x00, 0x20))
ENC_KEY = bytes(range(0x20, 0x40))
MAC_KEY = bytes(range(0x40, 0x60))
IDX_KEY = bytes(range(0x60, 0x80))
IV = bytes(range(0x10))
PWD_SALT = bytes(range(0xA0, 0xB0))
PWD_ITER = 10000
KEY_ID = 1

SAMPLES = [
    ('RRN', '880101-1234567', 'DIGITS'),
    ('ACCT', '110-1234-567890', 'DIGITS'),
    ('NAME', '홍길동', 'TRIM'),
    ('ADDR', '서울특별시 종로구 세종대로 1', 'NONE'),
    ('EMPTY', '', 'NONE'),
    ('LONG', 'A' * 200, 'NONE'),
]
PASSWORDS = ['Passw0rd!', '한글비밀번호1!', '공백 포함 긴 문장 암호 2026!']


def build():
    kek_enc, kek_mac = R.kek_subkeys(KEK)
    v = {
        'note': '시험 전용 벡터. 실제 키로 사용 금지.',
        'format_version': R.FMT_VERSION,
        'alg_id': R.ALG_AES256_CBC_HMAC_SHA256,
        'key_id': KEY_ID,
        'kek': R.hx(KEK),
        'kek_enc': R.hx(kek_enc),
        'kek_mac': R.hx(kek_mac),
        'enc_key': R.hx(ENC_KEY),
        'mac_key': R.hx(MAC_KEY),
        'idx_key': R.hx(IDX_KEY),
        'iv': R.hx(IV),
        'wrapped_enc_key': R.hx(R.wrap_key(ENC_KEY, KEK, IV)),
        'wrapped_mac_key': R.hx(R.wrap_key(MAC_KEY, KEK, IV)),
        'wrapped_idx_key': R.hx(R.wrap_key(IDX_KEY, KEK, IV)),
        'pwd_salt': R.hx(PWD_SALT),
        'pwd_iterations': PWD_ITER,
        'samples': [],
        'passwords': [],
    }
    for name, plain, norm in SAMPLES:
        v['samples'].append({
            'name': name,
            'plain': plain,
            'norm': norm,
            'cipher': R.hx(R.encrypt(plain, KEY_ID, ENC_KEY, MAC_KEY, IV)),
            'blind_index': R.hx(R.blind_index(plain, IDX_KEY, norm)),
        })
    for pw in PASSWORDS:
        v['passwords'].append({
            'plain': pw,
            'stored': R.hx(R.password_hash(pw, PWD_SALT, PWD_ITER)),
        })
    return v


def emit_sql(v, path):
    """PL/SQL 자체 시험이 읽을 벡터 적재 스크립트."""
    rows = [
        ('KEK', v['kek']), ('KEK_ENC', v['kek_enc']), ('KEK_MAC', v['kek_mac']),
        ('ENC_KEY', v['enc_key']), ('MAC_KEY', v['mac_key']), ('IDX_KEY', v['idx_key']),
        ('IV', v['iv']),
        ('WRAPPED_ENC_KEY', v['wrapped_enc_key']),
        ('WRAPPED_MAC_KEY', v['wrapped_mac_key']),
        ('WRAPPED_IDX_KEY', v['wrapped_idx_key']),
        ('PWD_SALT', v['pwd_salt']), ('PWD_ITER', str(v['pwd_iterations'])),
        ('KEY_ID', str(v['key_id'])),
    ]
    for s in v['samples']:
        rows.append(('PLAIN_' + s['name'], s['plain']))
        rows.append(('NORM_' + s['name'], s['norm']))
        rows.append(('CIPHER_' + s['name'], s['cipher']))
        rows.append(('BIDX_' + s['name'], s['blind_index']))
    for i, p in enumerate(v['passwords']):
        rows.append(('PWD_PLAIN_%d' % i, p['plain']))
        rows.append(('PWD_STORED_%d' % i, p['stored']))

    out = ["-- 자동 생성 파일. 직접 수정하지 말 것.",
           "-- 생성: python3 tools/refimpl/gen_vectors.py",
           "-- 시험 전용 벡터이며 실제 키로 사용해서는 안 된다.",
           "SET DEFINE OFF",
           "DELETE FROM SEC_KAT;"]
    for k, val in rows:
        out.append("INSERT INTO SEC_KAT (kat_name, kat_value) VALUES ('%s', '%s');"
                   % (k, val.replace("'", "''")))
    out.append("COMMIT;")
    out.append("SET DEFINE ON")
    out.append("")
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(out))


def emit_properties(v, path):
    """자바 연동 모듈이 읽을 벡터. java.util.Properties 로 읽는다.

    JSON 파서를 끌어들이지 않으려고 별도 형식을 하나 더 둔다. 연동 모듈은 외부
    의존성이 없어야 어느 프로젝트에나 그대로 넣을 수 있기 때문이다.
    파일은 UTF-8 로 쓰며, 자바 쪽에서 문자집합을 명시한 Reader 로 읽는다.
    """
    lines = ['# 자동 생성 파일. 직접 수정하지 말 것.',
             '# 생성: python3 tools/refimpl/gen_vectors.py',
             '# 시험 전용 벡터이며 실제 키로 사용해서는 안 된다.']

    def put(k, val):
        val = str(val).replace('\\', '\\\\')
        lines.append('%s=%s' % (k, val))

    for k in ('kek', 'kek_enc', 'kek_mac', 'enc_key', 'mac_key', 'idx_key', 'iv',
              'wrapped_enc_key', 'wrapped_mac_key', 'wrapped_idx_key',
              'pwd_salt', 'pwd_iterations', 'key_id'):
        put(k, v[k])
    for smp in v['samples']:
        put('sample.%s.plain'  % smp['name'], smp['plain'])
        put('sample.%s.norm'   % smp['name'], smp['norm'])
        put('sample.%s.cipher' % smp['name'], smp['cipher'])
        put('sample.%s.bidx'   % smp['name'], smp['blind_index'])
    put('sample.names', ','.join(smp['name'] for smp in v['samples']))
    for i, pw in enumerate(v['passwords']):
        put('pwd.%d.plain'  % i, pw['plain'])
        put('pwd.%d.stored' % i, pw['stored'])
    put('pwd.count', len(v['passwords']))

    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    v = build()
    jpath = os.path.join(root, 'tests', 'vectors', 'kat.json')
    with open(jpath, 'w', encoding='utf-8') as fh:
        json.dump(v, fh, ensure_ascii=False, indent=2)
    spath = os.path.join(root, 'sql', '09_test', '901_kat_data.sql')
    emit_sql(v, spath)
    ppath = os.path.join(root, 'tests', 'vectors', 'kat.properties')
    emit_properties(v, ppath)
    print('생성 완료:', jpath)
    print('생성 완료:', spath)
    print('생성 완료:', ppath)


if __name__ == '__main__':
    main()
