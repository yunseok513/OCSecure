# -*- coding: utf-8 -*-
"""PL/SQL 정적 점검.

오라클 인스턴스 없이도 잡을 수 있는 오류만 걸러낸다. 컴파일을 대신하지는 못하므로,
이 점검을 통과했다는 것이 동작을 보장하지는 않는다. 실 인스턴스에서 반드시
컴파일과 자체 시험을 거쳐야 한다.

점검 항목
  1. 패키지 명세와 본문의 짝이 맞는가
  2. END 뒤의 이름이 패키지 이름과 같은가
  3. 명세에 선언한 서브프로그램이 본문에 모두 정의되어 있는가
  4. 블록 종결자(/)가 CREATE 문마다 있는가
  5. 패키지 간 호출(PKG_X.foo)이 실제로 명세에 있는 이름을 가리키는가
  6. SQLERRM / SQLCODE 를 SQL 문 안에서 직접 쓰고 있지는 않은가
  7. SQL 문 안에서 지역 서브프로그램을 부르고 있지는 않은가
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RE_PKG = re.compile(
    r'CREATE\s+OR\s+REPLACE\s+PACKAGE\s+(BODY\s+)?([A-Z0-9_]+)\s+(?:AS|IS)\b',
    re.IGNORECASE)
RE_END = re.compile(r'^\s*END\s+([A-Z0-9_]+)\s*;', re.IGNORECASE | re.MULTILINE)
RE_SUB = re.compile(
    r'^\s*(FUNCTION|PROCEDURE)\s+([A-Z0-9_]+)', re.IGNORECASE | re.MULTILINE)
RE_CONST = re.compile(
    r'^\s*([A-Z0-9_]+)\s+CONSTANT\b', re.IGNORECASE | re.MULTILINE)
RE_TYPE = re.compile(
    r'^\s*TYPE\s+([A-Z0-9_]+)\s+IS\b', re.IGNORECASE | re.MULTILINE)
# PKG_로 시작하는 패키지에 대한 한정 호출만 본다. 오라클 내장 패키지는 대상이 아니다.
RE_CALL = re.compile(r'\b(PKG_[A-Z0-9_]+)\.([A-Z0-9_]+)', re.IGNORECASE)
# SQL 문 안에서는 SQLERRM 과 SQLCODE 를 직접 쓸 수 없다(PLS-00049 계열 오류).
# 반드시 PL/SQL 변수로 받아 두고 그 변수를 SQL 문에 넘겨야 한다.
# SQL 문을 세미콜론 단위로 자르면 PL/SQL 구조 때문에 경계가 어긋난다. 키워드에서
# 시작해 세미콜론까지 훑되, 블록 키워드를 만나면 거기서 끊는다.
RE_DML = re.compile(r'\b(INSERT|UPDATE|DELETE|MERGE|SELECT)\b[^;]*', re.IGNORECASE)
RE_DML_STOP = re.compile(r'\b(LOOP|THEN|BEGIN|ELSE|ELSIF|END)\b', re.IGNORECASE)
RE_ERRFN = re.compile(r'\b(SQLERRM|SQLCODE)\b', re.IGNORECASE)


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    return re.sub(r'--[^\n]*', '', text)


def strip_strings(text):
    """작은따옴표 문자열을 지운다. 오류 메시지 안의 이름을 호출로 오인하지 않게 한다."""
    return re.sub(r"'(?:''|[^'])*'", "''", text)


def split_units(text):
    """CREATE ... / 단위로 자른다. 종결자는 한 줄에 홀로 있는 '/' 이다."""
    units, cur = [], []
    for line in text.splitlines():
        if line.strip() == '/':
            units.append('\n'.join(cur))
            cur = []
        else:
            cur.append(line)
    if any(l.strip() for l in cur):
        units.append('\n'.join(cur))   # 종결자 없이 남은 꼬리
    return units


def collect_specs(files):
    """모든 파일에서 패키지 명세가 공개한 이름을 모은다."""
    public = {}
    for path in files:
        text = strip_comments(open(path, encoding='utf-8').read())
        for unit in split_units(text):
            m = RE_PKG.search(unit)
            if not m or m.group(1):        # 본문은 건너뛴다
                continue
            name = m.group(2).upper()
            names = {s.group(2).upper() for s in RE_SUB.finditer(unit)}
            names |= {c.group(1).upper() for c in RE_CONST.finditer(unit)}
            names |= {t.group(1).upper() for t in RE_TYPE.finditer(unit)}
            public[name] = names
    return public


def check_calls(path, public):
    """패키지 간 호출이 실제로 공개된 이름을 가리키는지 확인한다."""
    errs = []
    text = strip_strings(strip_comments(open(path, encoding='utf-8').read()))
    seen = set()
    for m in RE_CALL.finditer(text):
        pkg, member = m.group(1).upper(), m.group(2).upper()
        if pkg not in public or (pkg, member) in seen:
            continue
        seen.add((pkg, member))
        if member not in public[pkg]:
            errs.append('%s: %s.%s 은 %s 명세에 없는 이름이다'
                        % (os.path.basename(path), pkg, member, pkg))
    return errs


def dml_statements(text):
    """SQL 문으로 볼 수 있는 구간만 뽑는다. 주석과 문자열은 미리 지워져 있어야 한다."""
    out = []
    for m in RE_DML.finditer(text):
        stmt = m.group(0)
        stop = RE_DML_STOP.search(stmt)
        if stop:
            stmt = stmt[:stop.start()]
        out.append((m.group(1).upper(), stmt))
    return out


def check_sql_errfn(path):
    """SQLERRM / SQLCODE 가 SQL 문 안에 직접 놓였는지 본다.

    주석과 문자열을 지운 뒤 세미콜론으로 문장을 자르고, 첫 낱말이 DML 키워드인
    문장만 검사한다. PL/SQL 대입문이나 프로시저 호출의 인자로 쓰는 것은 허용되므로
    걸러내지 않는다.
    """
    errs = []
    text = strip_strings(strip_comments(open(path, encoding='utf-8').read()))
    for kind, stmt in dml_statements(text):
        m = RE_ERRFN.search(stmt)
        if m:
            errs.append('%s: %s 를 SQL 문(%s) 안에서 직접 쓰고 있다. '
                        'PL/SQL 변수로 먼저 받아서 넘겨야 한다'
                        % (os.path.basename(path), m.group(1).upper(), kind))
    return errs


def check_local_in_sql(path, public):
    """SQL 문 안에서 지역 서브프로그램을 부르는지 본다.

    익명 블록의 중첩 함수나 패키지 본문에만 있는 비공개 함수는 SQL 엔진에 보이지
    않는다. SQL 문 안에 그대로 쓰면 ORA-00904(부적절한 식별자) 가 난다. 값을 먼저
    PL/SQL 변수로 받아 두고 그 변수를 SQL 문에 넘겨야 한다.
    """
    errs = []
    text = strip_strings(strip_comments(open(path, encoding='utf-8').read()))

    for unit in split_units(text):
        m = RE_PKG.search(unit)
        pkg = m.group(2).upper() if m else None
        exposed = set(public.get(pkg, ())) if pkg else set()
        # 다른 패키지의 공개 이름은 어차피 한정 호출(PKG_X.foo)로 쓰므로 여기서는 보지 않는다.
        local = {d.group(2).upper() for d in RE_SUB.finditer(unit)} - exposed
        if not local:
            continue

        seen = set()
        for kind, stmt in dml_statements(unit):
            for name in local:
                if name in seen:
                    continue
                # 한정 호출(PKG_X.foo)은 대상이 아니므로 앞에 점이 없는 경우만 본다.
                if re.search(r'(?<![.\w])' + name + r'\s*\(', stmt, re.IGNORECASE):
                    seen.add(name)
                    errs.append('%s: SQL 문(%s) 안에서 지역 서브프로그램 %s 를 부르고 있다. '
                                'PL/SQL 변수로 먼저 받아서 넘겨야 한다'
                                % (os.path.basename(path), kind, name))
    return errs


def check_file(path):
    errs = []
    raw = open(path, encoding='utf-8').read()
    text = strip_comments(raw)

    specs, bodies = {}, {}
    for unit in split_units(text):
        m = RE_PKG.search(unit)
        if not m:
            continue
        is_body, name = bool(m.group(1)), m.group(2).upper()
        subs = {s.group(2).upper() for s in RE_SUB.finditer(unit)}
        (bodies if is_body else specs)[name] = subs

        ends = [e.group(1).upper() for e in RE_END.finditer(unit)]
        if not ends or ends[-1] != name:
            errs.append('%s: 패키지 %s 의 마지막 END 이름이 어긋난다 (%s)'
                        % (os.path.basename(path), name,
                           ends[-1] if ends else '없음'))

    n_create = len(re.findall(r'CREATE\s+OR\s+REPLACE', text, re.IGNORECASE))
    n_slash = len([l for l in raw.splitlines() if l.strip() == '/'])
    if n_create > n_slash:
        errs.append('%s: 종결자(/) 가 부족하다 (CREATE %d개 / 종결자 %d개)'
                    % (os.path.basename(path), n_create, n_slash))

    for name, spec_subs in specs.items():
        if name not in bodies:
            continue
        missing = spec_subs - bodies[name]
        if missing:
            errs.append('%s: %s 명세에 선언했으나 본문에 없다: %s'
                        % (os.path.basename(path), name, ', '.join(sorted(missing))))
    return errs


def main():
    pkg_files = sorted(glob.glob(os.path.join(ROOT, 'sql', '02_packages', '*.sql')))
    # 호출 점검은 예시와 시험 스크립트까지 넓혀서 본다.
    call_files = pkg_files + sorted(
        glob.glob(os.path.join(ROOT, 'sql', '04_admin', '*.sql'))
        + glob.glob(os.path.join(ROOT, 'sql', '08_sample', '*.sql'))
        + glob.glob(os.path.join(ROOT, 'sql', '09_test', '*.sql')))

    all_errs = []
    for f in pkg_files:
        all_errs.extend(check_file(f))

    public = collect_specs(pkg_files)
    for f in call_files:
        all_errs.extend(check_calls(f, public))
        all_errs.extend(check_sql_errfn(f))
        all_errs.extend(check_local_in_sql(f, public))

    for e in all_errs:
        print('  [오류] ' + e)
    print('점검 파일 %d개, 오류 %d건' % (len(call_files), len(all_errs)))
    return 1 if all_errs else 0


if __name__ == '__main__':
    sys.exit(main())
