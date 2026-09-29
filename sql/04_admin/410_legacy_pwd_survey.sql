-- 기존 비밀번호 저장값 실태 조사
-- 기존 시스템의 사용자 테이블을 읽을 수 있는 계정으로 실행한다.
--
-- 저장값을 직접 보지 않고도 생김새만으로 저장 방식을 상당히 좁힐 수 있다.
-- 여기서 나온 단서로 범위를 줄인 뒤, tools/legacy_pwd_probe.py 로 확정한다.
--
-- 이 조사는 저장값을 읽기만 하며 아무것도 바꾸지 않는다. 다만 저장값을 화면에
-- 그대로 띄우지 않도록 구성하였다. 실태 조사가 곧 유출 경로가 되어서는 안 된다.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET LINESIZE 200
SET FEEDBACK OFF

ACCEPT tbl CHAR PROMPT '  사용자 테이블(스키마.테이블): '
ACCEPT col CHAR PROMPT '  비밀번호 컬럼명            : '

PROMPT
PROMPT === 1. 컬럼 정의 ===
PROMPT     자료형이 RAW 나 BLOB 이면 이진값, VARCHAR2 면 문자열로 저장된 것이다.
SELECT column_name, data_type, data_length, nullable
  FROM all_tab_columns
 WHERE owner || '.' || table_name = UPPER('&tbl')
   AND column_name = UPPER('&col');

PROMPT
PROMPT === 2. 길이 분포 ===
PROMPT     길이가 한 가지로 모여 있으면 해시일 가능성이 높다.
PROMPT     32/40/64/128 은 16진 표기의 MD5/SHA-1/SHA-256/SHA-512 길이이고,
PROMPT     24/28/44/88 은 Base64 표기의 같은 알고리즘 길이다.
PROMPT     60 이면 bcrypt, 54 면 이미 OCSecure 형식이다.
PROMPT     길이가 제각각이면 평문이거나 가변 길이 암호화일 수 있다.
SELECT LENGTH(&col) AS val_len, COUNT(*) AS cnt,
       ROUND(RATIO_TO_REPORT(COUNT(*)) OVER () * 100, 1) AS pct
  FROM &tbl
 WHERE &col IS NOT NULL
 GROUP BY LENGTH(&col)
 ORDER BY cnt DESC
 FETCH FIRST 20 ROWS ONLY;

PROMPT
PROMPT === 3. 문자 구성 ===
PROMPT     저장값 자체는 보여 주지 않고 어떤 문자로 이루어졌는지만 센다.
SELECT CASE
         WHEN REGEXP_LIKE(&col, '^\$2[aby]\$')            THEN 'bcrypt 형식($2a$ 등으로 시작)'
         WHEN REGEXP_LIKE(&col, '^\{')                    THEN '접두사 표기({bcrypt} 등으로 시작)'
         WHEN REGEXP_LIKE(&col, '^[0-9a-f]+$')            THEN '16진 소문자만'
         WHEN REGEXP_LIKE(&col, '^[0-9A-F]+$')            THEN '16진 대문자만'
         WHEN REGEXP_LIKE(&col, '^[A-Za-z0-9+/]+=*$')     THEN 'Base64 문자만'
         WHEN REGEXP_LIKE(&col, '[가-힣]')                THEN '한글 포함 (평문 가능성)'
         ELSE '그 밖의 문자 포함 (평문 가능성)'
       END AS shape,
       COUNT(*) AS cnt
  FROM &tbl
 WHERE &col IS NOT NULL
 GROUP BY CASE
         WHEN REGEXP_LIKE(&col, '^\$2[aby]\$')            THEN 'bcrypt 형식($2a$ 등으로 시작)'
         WHEN REGEXP_LIKE(&col, '^\{')                    THEN '접두사 표기({bcrypt} 등으로 시작)'
         WHEN REGEXP_LIKE(&col, '^[0-9a-f]+$')            THEN '16진 소문자만'
         WHEN REGEXP_LIKE(&col, '^[0-9A-F]+$')            THEN '16진 대문자만'
         WHEN REGEXP_LIKE(&col, '^[A-Za-z0-9+/]+=*$')     THEN 'Base64 문자만'
         WHEN REGEXP_LIKE(&col, '[가-힣]')                THEN '한글 포함 (평문 가능성)'
         ELSE '그 밖의 문자 포함 (평문 가능성)'
       END
 ORDER BY cnt DESC;

PROMPT
PROMPT === 3의2. 패딩 문자 ===
PROMPT     Base64 의 끝 패딩으로 원래 바이트 수가 확정된다.
PROMPT     24자가 '=='로 끝나면 16바이트, 44자가 '='로 끝나면 32바이트다.
PROMPT     그렇지 않다면 해시도 블록 암호도 아니므로 다시 봐야 한다.
SELECT LENGTH(&col) AS val_len,
       CASE WHEN SUBSTR(&col, -2) = '==' THEN '== 로 끝남'
            WHEN SUBSTR(&col, -1) = '='  THEN '=  로 끝남'
            ELSE '패딩 없음' END AS padding,
       COUNT(*) AS cnt
  FROM &tbl
 WHERE &col IS NOT NULL
 GROUP BY LENGTH(&col),
       CASE WHEN SUBSTR(&col, -2) = '==' THEN '== 로 끝남'
            WHEN SUBSTR(&col, -1) = '='  THEN '=  로 끝남'
            ELSE '패딩 없음' END
 ORDER BY 1, 3 DESC;

PROMPT
PROMPT === 4. 중복 저장값 ===
PROMPT     이것이 솔트 유무를 가르는 결정적 단서다.
PROMPT     서로 다른 사용자가 같은 저장값을 갖고 있다면 솔트가 없다는 뜻이다.
PROMPT     같은 비밀번호를 쓰는 사람이 여럿인 것은 흔한 일이므로, 중복이 전혀 없다면
PROMPT     사용자마다 다른 값이 섞여 들어갔다고 볼 수 있다.
PROMPT     저장값 자체는 보여 주지 않고 중복 건수만 센다.
SELECT COUNT(*)                    AS total_users,
       COUNT(DISTINCT &col)        AS distinct_values,
       COUNT(*) - COUNT(DISTINCT &col) AS duplicated
  FROM &tbl
 WHERE &col IS NOT NULL;

PROMPT
PROMPT === 4의2. 길이와 계정 생성 시기의 관계 ===
PROMPT     길이가 두 가지로 갈릴 때 원인을 가르는 조사다.
PROMPT     옛 길이가 옛 계정에 몰려 있으면 알고리즘이 도중에 바뀐 것이고,
PROMPT     생성 시기와 무관하게 섞여 있으면 길이를 가르는 것은 다른 요인,
PROMPT     곧 비밀번호 자체의 길이일 가능성이 높다. 그 경우 해시가 아니라
PROMPT     양방향 암호화를 의심해야 한다.
PROMPT     날짜 컬럼이 없으면 빈 값을 넣고 넘어간다.
ACCEPT dtcol CHAR PROMPT '  계정 생성일 컬럼명(없으면 엔터): '

SELECT TO_CHAR(&dtcol, 'YYYY')  AS created_year,
       LENGTH(&col)             AS val_len,
       COUNT(*)                 AS cnt
  FROM &tbl
 WHERE &col IS NOT NULL
 GROUP BY TO_CHAR(&dtcol, 'YYYY'), LENGTH(&col)
 ORDER BY 1, 2;

PROMPT
PROMPT === 5. 다음 단계 ===
PROMPT     시험계에 계정을 하나 만들고 비밀번호를 정해 등록한 뒤, 그 계정의
PROMPT     저장값을 조회하여 아래와 같이 확정한다. 운영계 사용자의 비밀번호로
PROMPT     시도하지 말 것.
PROMPT
PROMPT       python3 tools/legacy_pwd_probe.py \
PROMPT              --plain '정한비밀번호' --stored '조회한저장값' --id '아이디'
PROMPT
PROMPT     길이가 24자와 44자 두 가지로 갈리는 경우에는, 시험 계정의 비밀번호를
PROMPT     40자 이상으로 길게 정하는 것이 결정적이다. 해시라면 비밀번호가 아무리
PROMPT     길어도 저장값 길이는 그대로지만, 블록 암호라면 64자로 늘어난다.
PROMPT     단 한 건으로 두 가설을 가를 수 있다.
PROMPT

SET FEEDBACK ON
