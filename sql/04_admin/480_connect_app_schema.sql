-- 업무 계정(응용 스키마) 연결
-- SYS 또는 그에 준하는 권한으로, 대상 PDB 에서 실행한다. 300_grants.sql 다음에 한다.
--
-- 이미 있는 업무 계정이 암호 모듈을 쓸 수 있도록 지정한 계정에 세 가지를 한다.
--   1. 역할 OCS_ROLE_APP 을 준다.
--   2. PKG_SECURE_API 와 OCS_OWNER 의 FN_ 함수 전부에 대한 실행 권한을 계정에 직접
--      준다. 역할로 준 권한은 뷰나 저장 프로시저 안에서 인정되지 않으므로 직접 준다.
--   3. FN_ 함수 이름의 시노님을 그 계정에 만든다. 그러면 FN_ENC_RRN(...) 처럼 소유자
--      이름 없이 부를 수 있다.
--
-- 업무 계정의 비밀번호와 기존 권한과 quota 는 건드리지 않는다. 업무 계정이 여러
-- 개이면 계정마다 한 번씩 실행한다. 다시 실행해도 안전하다. 암호 모듈 자체의 계정
-- (OCS_OWNER, OCS_KEYADM, OCS_AUDITOR)과 SYS, SYSTEM 에는 쓰지 않는다. 권한 부여는
-- 통합 감사에 남는다.
--
-- 이 권한은 응용이 암복호화 API 를 직접 부를 수 있는 것과 같은 수준이다. 열어 주어도
-- 되는 계정인지 확인한 뒤에 실행한다.

SET ECHO OFF
SET VERIFY OFF
SET SERVEROUTPUT ON SIZE 100000

ACCEPT target_schema CHAR PROMPT '연결할 업무 계정(응용 스키마) 이름: '

DECLARE
  v_schema VARCHAR2(128);
  v_n      NUMBER;
  v_cnt    PLS_INTEGER := 0;
BEGIN
  v_schema := DBMS_ASSERT.SIMPLE_SQL_NAME(UPPER(TRIM('&target_schema')));

  IF v_schema IN ('OCS_OWNER', 'OCS_KEYADM', 'OCS_AUDITOR', 'SYS', 'SYSTEM') THEN
    RAISE_APPLICATION_ERROR(-20001, v_schema || ' 에는 함수 이름을 열 수 없다');
  END IF;

  SELECT COUNT(*) INTO v_n FROM dba_users WHERE username = v_schema;
  IF v_n = 0 THEN
    RAISE_APPLICATION_ERROR(-20002, v_schema || ' 스키마가 없다');
  END IF;

  EXECUTE IMMEDIATE 'GRANT OCS_ROLE_APP TO ' || v_schema;
  EXECUTE IMMEDIATE 'GRANT EXECUTE ON OCS_OWNER.PKG_SECURE_API TO ' || v_schema;

  FOR f IN (SELECT object_name FROM dba_objects
             WHERE owner = 'OCS_OWNER' AND object_type = 'FUNCTION'
               AND object_name LIKE 'FN\_%' ESCAPE '\'
             ORDER BY object_name) LOOP
    EXECUTE IMMEDIATE 'GRANT EXECUTE ON OCS_OWNER.' || f.object_name || ' TO ' || v_schema;
    EXECUTE IMMEDIATE 'CREATE OR REPLACE SYNONYM ' || v_schema || '.' || f.object_name
                      || ' FOR OCS_OWNER.' || f.object_name;
    v_cnt := v_cnt + 1;
  END LOOP;

  IF v_cnt = 0 THEN
    RAISE_APPLICATION_ERROR(-20003, 'OCS_OWNER 에 FN_ 함수가 없다. 220_fn_wrappers.sql 을 먼저 실행한다');
  END IF;
  DBMS_OUTPUT.PUT_LINE(v_schema || ' 에 역할, 패키지 실행 권한, 함수 ' || v_cnt || '개의 실행 권한과 시노님을 만들었다.');
END;
/

PROMPT
PROMPT 위 문구의 함수 개수와 OCS_OWNER 의 FN_ 함수 수가 같아야 한다.
SELECT COUNT(*) AS ocs_fn_함수_수 FROM dba_objects
 WHERE owner = 'OCS_OWNER' AND object_type = 'FUNCTION' AND object_name LIKE 'FN\_%' ESCAPE '\';

UNDEFINE target_schema
