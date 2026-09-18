#!/bin/sh
# 자바 연동 모듈 컴파일과 자체 시험.
#
# 외부 의존성이 없으므로 빌드 도구 없이 javac 만으로 확인할 수 있다.
# 실제 프로젝트에서는 java/pom.xml 을 쓰거나 소스를 그대로 가져다 넣으면 된다.
set -e
cd "$(dirname "$0")/.."

OUT="${TMPDIR:-/tmp}/ocsecure-java-build"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "=== 자바 컴파일 ==="
javac -encoding UTF-8 -Xlint:all -d "$OUT" $(find java/src -name '*.java')
echo "  [정상] 경고 없이 컴파일되었다"

echo "=== 자바 자체 시험 (고정 시험 벡터 대조) ==="
java -Dstdout.encoding=UTF-8 -cp "$OUT" \
     ocsecure.client.OcsSelfTest tests/vectors/kat.properties
