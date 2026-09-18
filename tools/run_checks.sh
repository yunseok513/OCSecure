#!/bin/sh
# OCSecure 개발 점검. 오라클 없이 돌릴 수 있는 검증만 수행한다.
#
#   1. 참조 구현 시험
#   2. 고정 시험 벡터 재생성 후 변경 여부 확인
#   3. PL/SQL 정적 점검
#   4. 자바 연동 모듈 컴파일과 고정 시험 벡터 대조
#
# 실 인스턴스에서의 컴파일과 자체 시험(sql/09_test/902_selftest.sql)은
# 이 스크립트로 대신할 수 없다.
set -e
cd "$(dirname "$0")/.."

echo "=== 1. 참조 구현 시험 ==="
python3 -m unittest discover -s tests -q

echo "=== 2. 고정 시험 벡터 최신 여부 ==="
# 벡터를 다시 만들어 기존 파일과 바이트 단위로 비교한다. 참조 구현을 고치고
# 벡터를 다시 만들지 않은 채 커밋하는 사고를 막기 위한 점검이다.
BK="${TMPDIR:-/tmp}/ocsecure-vec-check"
rm -rf "$BK"; mkdir -p "$BK"
cp tests/vectors/kat.json tests/vectors/kat.properties sql/09_test/901_kat_data.sql "$BK/"
python3 tools/refimpl/gen_vectors.py >/dev/null
for f in tests/vectors/kat.json tests/vectors/kat.properties sql/09_test/901_kat_data.sql; do
  if ! cmp -s "$f" "$BK/$(basename "$f")"; then
    echo "  [오류] $f 이(가) 참조 구현과 어긋난다. 재생성 결과를 확인하고 함께 커밋할 것."
    exit 1
  fi
done
echo "  [정상] 시험 벡터가 참조 구현과 일치한다"

echo "=== 3. PL/SQL 정적 점검 ==="
python3 tools/lint_plsql.py

echo "=== 4. 자바 연동 모듈 ==="
./tools/build_java.sh | tail -1

echo "=== 모든 점검 통과 ==="
