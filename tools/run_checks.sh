#!/bin/sh
# 유닉스 계열용 얇은 껍데기. 실제 점검은 tools/run_checks.py 가 한다.
# 윈도우에서는 tools\run_checks.bat 을 쓴다.
#
#   ./tools/run_checks.sh
#   ./tools/run_checks.sh --only java
#   ./tools/run_checks.sh --strict
cd "$(dirname "$0")/.." || exit 1

for PY in python3 python; do
  if command -v "$PY" >/dev/null 2>&1; then
    exec "$PY" tools/run_checks.py "$@"
  fi
done

echo "파이썬을 찾을 수 없다. python3 또는 python 이 PATH 에 있어야 한다." >&2
exit 1
