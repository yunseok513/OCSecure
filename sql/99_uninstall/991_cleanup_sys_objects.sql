-- SYS 계정에 잘못 만든 암호 모듈 객체 정리
-- SYS 로, 대상 PDB 에서 실행한다.
--
-- 020, 030, 090~220 은 OCS_OWNER 로 실행해야 한다. 실수로 SYS 로 실행하면 같은
-- 객체가 SYS 스키마에 만들어진다. 이 스크립트는 그것만 지운다. OCS_OWNER 의 객체와
-- 다른 계정과 문맥과 역할은 건드리지 않는다.
--
-- 지우는 대상은 아래 이름 목록에 있는 것뿐이며, 소유자가 SYS 인 것만 찾는다. 다른
-- SYS 객체는 이름이 달라 대상이 되지 않는다. 지우기 전에 목록을 보여 주고 확인을 받는다.
-- 계정 전체를 지우는 990_drop_all.sql 과 다르다. 운영계에서도 실행할 수 있으나,
-- 그 인스턴스에서 SYS 에 이 이름의 객체가 정말 잘못 만든 것인지 먼저 확인할 것.

SET SERVEROUTPUT ON SIZE 100000
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON

PROMPT
PROMPT === 지금 접속한 곳 ===
SELECT SYS_CONTEXT('USERENV','CON_NAME')      AS 컨테이너,
       SYS_CONTEXT('USERENV','SESSION_USER')  AS 접속계정
  FROM dual;

PROMPT
PROMPT === SYS 에 있는 암호 모듈 객체 (지울 대상) ===
SELECT object_type, object_name, status, TO_CHAR(created, 'YYYY-MM-DD HH24:MI') AS created
  FROM dba_objects
 WHERE owner = 'SYS'
   AND ( object_name IN ('SEC_CONFIG', 'SEC_DOMAIN', 'SEC_REVEAL_GRANT', 'SEC_ADMIN_GRANT',
                         'SEC_KEY', 'SEC_AUDIT_LOG', 'SEC_REVEAL_USAGE', 'SEC_REKEY_JOB', 'SEC_KAT',
                         'V_SEC_SESSION_ROLES', 'V_SEC_EFFECTIVE_REVEAL', 'V_SEC_KEY_STATUS',
                         'SEQ_SEC_KEY_ID',
                         'PKG_SEC_ERR', 'PKG_PROVIDER_DBMS', 'PKG_CRYPTO_FMT', 'PKG_AUDIT',
                         'PKG_KEK_PROVIDER', 'PKG_KEY_STORE', 'PKG_CRYPTO_CORE', 'PKG_AUTHZ',
                         'PKG_APP_CONTEXT', 'PKG_KEY_ADMIN', 'PKG_CRYPTO_POLICY', 'PKG_LEGACY_PWD',
                         'PKG_SECURE_API', 'PKG_REKEY')
         OR (object_type = 'FUNCTION' AND object_name LIKE 'FN\_%' ESCAPE '\'
             AND object_name IN
               ('FN_PROTECT', 'FN_REVEAL', 'FN_MASKED', 'FN_SHOW', 'FN_SEARCH_OF', 'FN_ALLOWED',
                'FN_ENC_RRN', 'FN_DEC_RRN', 'FN_MASK_RRN', 'FN_IDX_RRN',
                'FN_ENC_NAME', 'FN_DEC_NAME', 'FN_MASK_NAME', 'FN_IDX_NAME',
                'FN_ENC_ACCOUNT', 'FN_DEC_ACCOUNT', 'FN_MASK_ACCOUNT', 'FN_IDX_ACCOUNT',
                'FN_MAKE_PWD', 'FN_VERIFY_PWD', 'FN_PWD_STALE', 'FN_MAKE_PWD_STR',
                'FN_CHECK_PWD', 'FN_PWD_STATE', 'FN_READY')) )
   AND object_type IN ('TABLE', 'VIEW', 'SEQUENCE', 'PACKAGE', 'PACKAGE BODY', 'FUNCTION')
 ORDER BY object_type, object_name;

PROMPT
PROMPT 위 목록이 SYS 에 잘못 만들어진 것이 맞는지 확인하고, 맞으면 DROP 이라고 입력한다.
ACCEPT ok CHAR PROMPT '  지우려면 DROP 이라고 입력하시오: '

DECLARE
  v_ok  VARCHAR2(20) := '&ok';
  v_cnt PLS_INTEGER := 0;

  PROCEDURE try(p_sql IN VARCHAR2) IS
  BEGIN
    EXECUTE IMMEDIATE p_sql;
    v_cnt := v_cnt + 1;
    DBMS_OUTPUT.PUT_LINE('  지움: ' || p_sql);
  EXCEPTION
    WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE('  [실패] ' || p_sql || ' : ' || SQLERRM);
  END try;
BEGIN
  IF v_ok <> 'DROP' THEN
    DBMS_OUTPUT.PUT_LINE('취소하였다. 아무것도 지우지 않았다.');
    RETURN;
  END IF;
  IF SYS_CONTEXT('USERENV', 'SESSION_USER') <> 'SYS' THEN
    DBMS_OUTPUT.PUT_LINE('SYS 로 접속하여 실행하십시오. 아무것도 지우지 않았다.');
    RETURN;
  END IF;
  IF SYS_CONTEXT('USERENV', 'CON_NAME') = 'CDB$ROOT' THEN
    DBMS_OUTPUT.PUT_LINE('컨테이너 최상위입니다. 대상 PDB 로 옮긴 뒤 실행하십시오. 아무것도 지우지 않았다.');
    RETURN;
  END IF;

  -- 함수와 패키지, 뷰, 표, 시퀀스 순서로 지운다. 표의 인덱스와 식별 컬럼의 내부
  -- 시퀀스는 표와 함께 사라진다.
  FOR o IN (SELECT object_name FROM dba_objects
             WHERE owner = 'SYS' AND object_type = 'FUNCTION'
               AND object_name IN
                 ('FN_PROTECT', 'FN_REVEAL', 'FN_MASKED', 'FN_SHOW', 'FN_SEARCH_OF', 'FN_ALLOWED',
                  'FN_ENC_RRN', 'FN_DEC_RRN', 'FN_MASK_RRN', 'FN_IDX_RRN',
                  'FN_ENC_NAME', 'FN_DEC_NAME', 'FN_MASK_NAME', 'FN_IDX_NAME',
                  'FN_ENC_ACCOUNT', 'FN_DEC_ACCOUNT', 'FN_MASK_ACCOUNT', 'FN_IDX_ACCOUNT',
                  'FN_MAKE_PWD', 'FN_VERIFY_PWD', 'FN_PWD_STALE', 'FN_MAKE_PWD_STR',
                  'FN_CHECK_PWD', 'FN_PWD_STATE', 'FN_READY')) LOOP
    try('DROP FUNCTION SYS.' || o.object_name);
  END LOOP;

  FOR o IN (SELECT object_name FROM dba_objects
             WHERE owner = 'SYS' AND object_type = 'PACKAGE'
               AND object_name IN
                 ('PKG_SEC_ERR', 'PKG_PROVIDER_DBMS', 'PKG_CRYPTO_FMT', 'PKG_AUDIT',
                  'PKG_KEK_PROVIDER', 'PKG_KEY_STORE', 'PKG_CRYPTO_CORE', 'PKG_AUTHZ',
                  'PKG_APP_CONTEXT', 'PKG_KEY_ADMIN', 'PKG_CRYPTO_POLICY', 'PKG_LEGACY_PWD',
                  'PKG_SECURE_API', 'PKG_REKEY')) LOOP
    try('DROP PACKAGE SYS.' || o.object_name);
  END LOOP;

  FOR o IN (SELECT object_name FROM dba_objects
             WHERE owner = 'SYS' AND object_type = 'VIEW'
               AND object_name IN
                 ('V_SEC_SESSION_ROLES', 'V_SEC_EFFECTIVE_REVEAL', 'V_SEC_KEY_STATUS')) LOOP
    try('DROP VIEW SYS.' || o.object_name);
  END LOOP;

  FOR o IN (SELECT object_name FROM dba_objects
             WHERE owner = 'SYS' AND object_type = 'TABLE'
               AND object_name IN
                 ('SEC_CONFIG', 'SEC_DOMAIN', 'SEC_REVEAL_GRANT', 'SEC_ADMIN_GRANT',
                  'SEC_KEY', 'SEC_AUDIT_LOG', 'SEC_REVEAL_USAGE', 'SEC_REKEY_JOB', 'SEC_KAT')) LOOP
    try('DROP TABLE SYS.' || o.object_name || ' CASCADE CONSTRAINTS PURGE');
  END LOOP;

  FOR o IN (SELECT object_name FROM dba_objects
             WHERE owner = 'SYS' AND object_type = 'SEQUENCE'
               AND object_name = 'SEQ_SEC_KEY_ID') LOOP
    try('DROP SEQUENCE SYS.' || o.object_name);
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('');
  DBMS_OUTPUT.PUT_LINE(v_cnt || '개를 지웠다.');
END;
/

PROMPT
PROMPT === 남은 SYS 의 암호 모듈 객체 (비어 있어야 정상) ===
SELECT object_type, object_name
  FROM dba_objects
 WHERE owner = 'SYS'
   AND ( object_name IN ('SEC_CONFIG', 'SEC_DOMAIN', 'SEC_REVEAL_GRANT', 'SEC_ADMIN_GRANT',
                         'SEC_KEY', 'SEC_AUDIT_LOG', 'SEC_REVEAL_USAGE', 'SEC_REKEY_JOB', 'SEC_KAT',
                         'V_SEC_SESSION_ROLES', 'V_SEC_EFFECTIVE_REVEAL', 'V_SEC_KEY_STATUS',
                         'SEQ_SEC_KEY_ID',
                         'PKG_SEC_ERR', 'PKG_PROVIDER_DBMS', 'PKG_CRYPTO_FMT', 'PKG_AUDIT',
                         'PKG_KEK_PROVIDER', 'PKG_KEY_STORE', 'PKG_CRYPTO_CORE', 'PKG_AUTHZ',
                         'PKG_APP_CONTEXT', 'PKG_KEY_ADMIN', 'PKG_CRYPTO_POLICY', 'PKG_LEGACY_PWD',
                         'PKG_SECURE_API', 'PKG_REKEY')
         OR (object_type = 'FUNCTION' AND object_name LIKE 'FN\_%' ESCAPE '\'
             AND object_name IN
               ('FN_PROTECT', 'FN_REVEAL', 'FN_MASKED', 'FN_SHOW', 'FN_SEARCH_OF', 'FN_ALLOWED',
                'FN_ENC_RRN', 'FN_DEC_RRN', 'FN_MASK_RRN', 'FN_IDX_RRN',
                'FN_ENC_NAME', 'FN_DEC_NAME', 'FN_MASK_NAME', 'FN_IDX_NAME',
                'FN_ENC_ACCOUNT', 'FN_DEC_ACCOUNT', 'FN_MASK_ACCOUNT', 'FN_IDX_ACCOUNT',
                'FN_MAKE_PWD', 'FN_VERIFY_PWD', 'FN_PWD_STALE', 'FN_MAKE_PWD_STR',
                'FN_CHECK_PWD', 'FN_PWD_STATE', 'FN_READY')) )
   AND object_type IN ('TABLE', 'VIEW', 'SEQUENCE', 'PACKAGE', 'PACKAGE BODY', 'FUNCTION')
 ORDER BY object_type, object_name;

PROMPT
PROMPT 비어 있으면 정리가 끝난 것이다. 설치 매뉴얼의 스키마 객체와 패키지 단계(3.4)를
PROMPT OCS_OWNER 로 접속하여 처음부터 다시 실행한다. 이 스크립트는 OCS_OWNER 의
PROMPT 객체를 건드리지 않았다.

SET FEEDBACK ON
