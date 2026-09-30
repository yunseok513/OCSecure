-- 기존 암호화 키의 소재 조사 (데이터베이스 쪽)
-- 기존 시스템의 사전을 읽을 수 있는 계정으로 실행한다. 읽기만 하며 아무것도 바꾸지 않는다.
--
-- 주민등록번호 컬럼의 저장값이 Base64 24자, 곧 16바이트라는 것은 128비트 블록
-- 암호의 한 블록이라는 뜻이다. 13자리 주민등록번호에 PKCS5 패딩을 붙이면 정확히
-- 한 블록이 되므로 AES, SEED, ARIA 가운데 하나로 보인다. 어느 쪽이든 키가 있어야
-- 되살릴 수 있고, 키를 찾지 못하면 그 자료는 복구할 수 없다. 이 사업 최대의
-- 위험이므로 가장 먼저 확인한다.
--
-- 암호화를 데이터베이스 안에서 했다면 흔적이 사전에 남는다. 이 스크립트는 그
-- 흔적을 훑는다. 아무것도 나오지 않으면 암호화는 애플리케이션 쪽에서 한 것이므로
-- 원본과 설정 파일을 뒤져야 한다. 어디를 볼지는 docs/90 에 적어 두었다.
--
-- 기존 시스템은 오래된 판일 수 있으므로 옛 문법만 쓴다. REGEXP_LIKE 와 투명
-- 데이터 암호화 관련 사전은 오라클 10g 부터 있으므로 여기서는 쓰지 않는다.
-- LIKE 와 UNION ALL 만으로 같은 일을 한다.

SET SERVEROUTPUT ON SIZE 1000000
SET LINESIZE 200
SET PAGESIZE 200
SET FEEDBACK OFF

COLUMN 판 FORMAT A40
COLUMN owner FORMAT A20
COLUMN name FORMAT A32
COLUMN type FORMAT A14
COLUMN referenced_name FORMAT A26
COLUMN table_name FORMAT A32
COLUMN column_name FORMAT A32
COLUMN 걸린말 FORMAT A16

PROMPT
PROMPT === 0. 데이터베이스 판 ===
SELECT product || ' ' || version AS 판
  FROM product_component_version
 WHERE product LIKE 'Oracle%';

PROMPT
PROMPT === 1. 암호 관련 내장 패키지를 쓰는 객체 ===
SELECT owner, name, type, referenced_name
  FROM all_dependencies
 WHERE referenced_name IN ('DBMS_CRYPTO', 'DBMS_OBFUSCATION_TOOLKIT', 'UTL_ENCODE', 'UTL_RAW')
   AND owner NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OLAPSYS',
                     'GSMADMIN_INTERNAL','AUDSYS','DVSYS','LBACSYS','APPQOSSYS','DBSNMP',
                     'OCS_OWNER')
 ORDER BY owner, name;

PROMPT
PROMPT === 2. 원본에 암호 관련 낱말이 있는 객체 ===
-- 이름과 걸린 낱말만 보여 준다. 원본 줄은 찍지 않는다. 화면과 기록에 키가 남으면 안 된다.
SELECT DISTINCT s.owner, s.name, s.type, k.w AS 걸린말
  FROM all_source s,
       (SELECT 'ENCRYPT' AS w FROM dual
        UNION ALL SELECT 'DECRYPT' FROM dual
        UNION ALL SELECT 'CIPHER'  FROM dual
        UNION ALL SELECT 'SECRET'  FROM dual
        UNION ALL SELECT 'ARIA'    FROM dual
        UNION ALL SELECT 'SEED'    FROM dual
        UNION ALL SELECT 'CRYPT'   FROM dual) k
 WHERE s.owner NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OLAPSYS',
                       'GSMADMIN_INTERNAL','AUDSYS','DVSYS','LBACSYS','APPQOSSYS','DBSNMP',
                       'OCS_OWNER')
   AND UPPER(s.text) LIKE '%' || k.w || '%'
 ORDER BY 1, 2, 4;

PROMPT
PROMPT === 3. 키 보관용으로 보이는 테이블 ===
SELECT DISTINCT c.owner, c.table_name, c.column_name, k.w AS 걸린말
  FROM all_tab_columns c,
       (SELECT 'CRYPT'  AS w FROM dual
        UNION ALL SELECT 'CIPHER'   FROM dual
        UNION ALL SELECT 'SECRET'   FROM dual
        UNION ALL SELECT 'KEYSTORE' FROM dual
        UNION ALL SELECT 'ENCKEY'   FROM dual
        UNION ALL SELECT 'ENC_KEY'  FROM dual
        UNION ALL SELECT 'KEY_'     FROM dual
        UNION ALL SELECT '_KEY'     FROM dual
        UNION ALL SELECT 'SALT'     FROM dual) k
 WHERE c.owner NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OLAPSYS',
                       'GSMADMIN_INTERNAL','AUDSYS','DVSYS','LBACSYS','APPQOSSYS','DBSNMP',
                       'OCS_OWNER')
   AND (UPPER(c.table_name)  LIKE '%' || k.w || '%'
        OR UPPER(c.column_name) LIKE '%' || k.w || '%')
 ORDER BY 1, 2, 3;

PROMPT
PROMPT 1번과 2번에 이름이 나오면 그 객체의 원본을 직접 보아야 한다.
PROMPT   SELECT text FROM all_source WHERE owner='<소유자>' AND name='<이름>' ORDER BY line;
PROMPT 아무것도 나오지 않으면 암호화는 애플리케이션 쪽에서 한 것이다.
PROMPT
PROMPT 3번의 LIKE 에는 밑줄이 한 글자 대신으로 쓰이므로 KEY_ 와 _KEY 는 넓게 걸린다.
PROMPT 그만큼 관계없는 컬럼도 함께 나오므로 이름을 보고 추려야 한다.

SET FEEDBACK ON
