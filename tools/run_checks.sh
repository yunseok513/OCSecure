#!/bin/sh
# OCSecure 개발 점검. 오라클 없이 돌릴 수 있는 검증만 수행한다.
#
#   1. 참조 구현 시험
#   2. 고정 시험 벡터 재생성 후 변경 여부 확인
#   3. PL/SQL 정적 점검
#
# 실 인스턴스에서의 컴파일과 자체 시험(sql/09_test/902_selftest.sql)은
# 이 스크립트로 대신할 수 없다.
set -e
cd "$(dirname "$0")/.."

echo "=== 1. 참조 구현 시험 ==="
python3 -m unittest discover -s tests -q

echo "=== 2. 고정 시험 벡터 최신 여부 ==="
python3 tools/refimpl/gen_vectors.py >/dev/null
if ! git diff --quiet -- tests/vectors sql/09_test/901_kat_data.sql; then
  echo "  [오류] 시험 벡터가 참조 구현과 어긋난다. 재생성 결과를 확인하고 함께 커밋할 것."
  git --no-pager diff --stat -- tests/vectors sql/09_test/901_kat_data.sql
  exit 1
fi
echo "  [정상] 시험 벡터가 참조 구현과 일치한다"

echo "=== 3. PL/SQL 정적 점검 ==="
python3 tools/lint_plsql.py

echo "=== 모든 점검 통과 ==="
