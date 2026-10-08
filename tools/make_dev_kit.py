# -*- coding: utf-8 -*-
"""개발자 키트 만들기.

업무 프로그램 개발자에게 전달할 작은 묶음을 만든다. 설치 패키지와 달리 데이터베이스 설치
스크립트나 키 관리 도구는 담지 않는다. 담는 것은 자바 연동 라이브러리, 개발자 매뉴얼, 예제,
예시 테이블 스크립트와 시작 안내이다.

  python tools/make_dev_kit.py
"""
import datetime
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

README = """\
OCSecure 개발자 키트

이 키트로 업무 프로그램에서 개인정보 컬럼을 암호화해 저장하고 읽을 수 있다.
데이터베이스 설치와 키 관리는 담당자가 이미 해 두었다고 전제한다.

받아야 할 것 (담당자에게 요청한다)
  1. 접속 문자열    jdbc:oracle:thin:@호스트:포트/서비스명
  2. 개발용 계정과 암호
  3. 복호화 자격    평문을 확인해야 하는 도메인(RRN, NAME, PHONE, ACCOUNT)
  4. 개발 모드 여부 개발 인스턴스는 증표 키 없이 문맥을 세운다 (아래 4번)

시작 순서
  1. lib\\ocsecure-client-1.0.0.jar 와 오라클 JDBC 드라이버(ojdbc8.jar)를 프로젝트의 클래스패스에 넣는다.
  2. 개발자_매뉴얼.md 의 제1장과 제3장을 읽는다. 제3장의 예제가 전체 흐름이다.
  3. 예시 테이블이 필요하면 담당자에게 sql_cp949\\800_sample_member.sql 의 실행을 요청한다.
     (SQL*Plus 에서 업무 계정으로 실행한다. 한글이 들어 있으므로 반드시 sql_cp949 쪽을 쓴다.)
  4. 문맥을 세울 때
       개발 인스턴스(개발 모드)   new OcsSessionSupport(null)
       증표 키를 받은 환경         new OcsSessionSupport(new OcsAppProof(증표키))
     나머지 코드는 같다. 반납 전에 session.release(con) 을 finally 에서 반드시 호출한다.
  5. 쿼리에서는 FN_ENC_RRN(?), FN_IDX_RRN(?), FN_SHOW('RRN', 컬럼) 처럼 짧은 이름을 쓴다.

막혔을 때
  개발자_매뉴얼.md 제9장(오류와 예외 처리)에서 오류 번호를 찾는다.

지킬 것
  개인정보 평문을 로그, 세션, 캐시에 남기지 않는다.
  암호문 컬럼은 RAW(256), 색인 컬럼은 RAW(32), 비밀번호는 RAW(64) 로 잡는다.
  검색은 색인 컬럼으로 한다. 암호문 컬럼을 조건절에 쓰지 않는다.
  시험 자료는 실제 개인정보가 아닌 값으로 만든다.
"""


def main():
    stamp = datetime.datetime.now().strftime('%Y%m%d')
    name = 'ocsecure-dev-kit-%s' % stamp
    dest = os.path.join(ROOT, 'dist', name)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(os.path.join(dest, 'lib'))
    os.makedirs(os.path.join(dest, 'example'))
    os.makedirs(os.path.join(dest, 'sql_cp949'))

    # 자바 8 호환으로 연동 라이브러리를 묶는다.
    classes = os.path.join(dest, '_classes')
    os.makedirs(classes)
    sources = []
    for base, _d, files in os.walk(os.path.join(ROOT, 'java', 'src', 'main', 'java', 'ocsecure', 'client')):
        sources += [os.path.join(base, f) for f in files if f.endswith('.java')]
    subprocess.check_call(['javac', '--release', '8', '-Xlint:-options', '-encoding', 'UTF-8', '-d', classes]
                          + sorted(sources))
    subprocess.check_call(['jar', 'cf', os.path.join(dest, 'lib', 'ocsecure-client-1.0.0.jar'), '-C', classes, '.'])
    shutil.rmtree(classes)

    shutil.copy(os.path.join(ROOT, 'docs', '개발자', '개발자_매뉴얼.md'), os.path.join(dest, '개발자_매뉴얼.md'))
    for f in ('MemberExample.java', 'OcsWork.java'):
        shutil.copy(os.path.join(ROOT, 'java', 'src', 'example', 'java', 'ocsecure', 'example', f),
                    os.path.join(dest, 'example', f))
    for f in ('800_sample_member.sql', '890_drop_samples.sql'):
        shutil.copy(os.path.join(ROOT, 'sql_cp949', '08_sample', f), os.path.join(dest, 'sql_cp949', f))
    with open(os.path.join(dest, '시작안내.txt'), 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(README)

    zip_path = dest + '.zip'
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for base, _d, files in os.walk(dest):
            for f in files:
                full = os.path.join(base, f)
                z.write(full, os.path.join(name, os.path.relpath(full, dest)))
    print('만들었다:', os.path.relpath(zip_path, ROOT))
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            print('  ', n)
    shutil.rmtree(dest)   # 압축 파일만 남긴다


if __name__ == '__main__':
    main()
