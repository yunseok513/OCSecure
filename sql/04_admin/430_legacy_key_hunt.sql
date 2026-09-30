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

SET SERVEROUTPUT ON SIZE UNLIMITED
SET LINESIZE 200
SET PAGESIZE 200
SET FEEDBACK OFF

COLUMN owner        FORMAT A20
COLUMN name         FORMAT A32
COLUMN type         FORMAT A14
COLUMN line         FORMAT 99999
COLUMN text         FORMAT A70
COLUMN table_name   FORMAT A32
COLUMN column_name  FORMAT A32

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
PROMPT === 2. 원본에 키로 보이는 문자열이 있는 객체 ===
-- 이름만 보여 준다. 값 자체는 찍지 않는다. 화면과 기록에 키가 남으면 안 된다.
SELECT DISTINCT owner, name, type
  FROM all_source
 WHERE owner NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OLAPSYS',
                     'GSMADMIN_INTERNAL','AUDSYS','DVSYS','LBACSYS','APPQOSSYS','DBSNMP',
                     'OCS_OWNER')
   AND (UPPER(text) LIKE '%ENCRYPT%'
     OR UPPER(text) LIKE '%DECRYPT%'
     OR UPPER(text) LIKE '%CIPHER%'
     OR UPPER(text) LIKE '%SECRET%'
     OR UPPER(text) LIKE '%ARIA%'
     OR UPPER(text) LIKE '%SEED%'
     OR REGEXP_LIKE(text, 'KEY\s*(:=|=)', 'i'))
 ORDER BY owner, name;

PROMPT
PROMPT === 3. 키 보관용으로 보이는 테이블 ===
SELECT owner, table_name, column_name
  FROM all_tab_columns
 WHERE owner NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OLAPSYS',
                     'GSMADMIN_INTERNAL','AUDSYS','DVSYS','LBACSYS','APPQOSSYS','DBSNMP',
                     'OCS_OWNER')
   AND (REGEXP_LIKE(table_name,  '(CRYPT|CIPHER|SECRET|KEYSTORE|KEY_?(TAB|MST|INFO|MGMT))', 'i')
     OR REGEXP_LIKE(column_name, '(ENC_?KEY|CRYPT_?KEY|SECRET_?KEY|IV_?VAL|SALT)', 'i'))
 ORDER BY owner, table_name, column_name;

PROMPT
PROMPT === 4. 투명 데이터 암호화(TDE) 적용 여부 ===
-- TDE 라면 응용이 Base64 를 볼 일이 없으므로 이번 건과는 다르다. 확인만 한다.
SELECT owner, table_name, column_name, encryption_alg
  FROM dba_encrypted_columns
 ORDER BY owner, table_name;

PROMPT
PROMPT === 5. 지갑(wallet) 상태 ===
SELECT wrl_type, status, wallet_type FROM v$encryption_wallet;

PROMPT
PROMPT 1번과 2번에 이름이 나오면 그 객체의 원본을 직접 보아야 한다.
PROMPT   SELECT text FROM all_source WHERE owner='<소유자>' AND name='<이름>' ORDER BY line;
PROMPT 아무것도 나오지 않으면 암호화는 애플리케이션 쪽에서 한 것이다.
PROMPT 4번과 5번에서 권한 오류가 나면 그 부분만 건너뛰어도 된다.

SET FEEDBACK ON
