#!/bin/sh
# 자바 연동 모듈만 컴파일하고 자체 시험을 돌린다.
# 실제 작업은 tools/run_checks.py 가 한다. 윈도우에서는 다음과 같이 쓴다.
#   tools\run_checks.bat --only java
cd "$(dirname "$0")/.." || exit 1

for PY in python3 python; do
  if command -v "$PY" >/dev/null 2>&1; then
    exec "$PY" tools/run_checks.py --only java "$@"
  fi
done

echo "파이썬을 찾을 수 없다. python3 또는 python 이 PATH 에 있어야 한다." >&2
exit 1
