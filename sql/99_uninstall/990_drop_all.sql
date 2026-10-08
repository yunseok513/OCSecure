-- 전체 제거
--
-- ****************************************************************************
-- *  경고. 이 스크립트는 암호 모듈과 그 아래의 모든 키와 감사 기록을 지운다.    *
-- *  키를 지우면 그 키로 암호화한 모든 자료를 영구히 되살릴 수 없다.            *
-- *  운영계에서는 절대 실행하지 말 것.                                        *
-- ****************************************************************************
--
-- 쓰임새는 하나다. 설치 절차가 아무것도 없는 상태에서 처음부터 제대로 도는지
-- 확인하는 것이다. 고쳐 가며 쌓인 상태 위에서 도는 것과 깨끗한 상태에서 도는 것은
-- 다르며, 후자를 확인하지 않으면 실제 반입 때 무엇이 빠졌는지 알 수 없다.
--
-- SYS 또는 그에 준하는 권한으로 실행한다. 대상 컨테이너가 맞는지 먼저 확인할 것.
--
-- 업무 계정(응용 스키마)은 지우지 않으며 그 안의 표와 예시 객체도 건드리지 않는다.
-- 예시는 그 계정에서 08_sample/890_drop_samples.sql 로 지운다.

SET SERVEROUTPUT ON SIZE 100000
SET FEEDBACK OFF
SET DEFINE ON

PROMPT
PROMPT === 지금 접속한 곳 ===
SELECT SYS_CONTEXT('USERENV','CON_NAME') AS 컨테이너,
       SYS_CONTEXT('USERENV','SESSION_USER') AS 접속계정
  FROM dual;

PROMPT
PROMPT 위 컨테이너의 암호 모듈을 통째로 지운다. 되돌릴 수 없다.
ACCEPT ok CHAR PROMPT '  정말 지우려면 DROP 이라고 입력하시오: '

DECLARE
  v_ok  VARCHAR2(20) := '&ok';

  -- 실행하고 성공 여부를 돌려준다. 실패한 이유를 그대로 보여 준다. 없는 것을 지우려 한
  -- 경우는 호출하는 쪽이 먼저 걸러 내므로, 여기서의 실패는 실제로 지우지 못한 것이다.
  FUNCTION try_b(p_sql IN VARCHAR2) RETURN BOOLEAN IS
  BEGIN
    EXECUTE IMMEDIATE p_sql;
    DBMS_OUTPUT.PUT_LINE('  지움: ' || p_sql);
    RETURN TRUE;
  EXCEPTION
    WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE('  [실패] ' || p_sql || ' : ' || SQLERRM);
      RETURN FALSE;
  END try_b;

  PROCEDURE try(p_sql IN VARCHAR2) IS
    v_dummy BOOLEAN;
  BEGIN
    v_dummy := try_b(p_sql);
  END try;

  -- 없어도 되는 것을 지울 때 쓴다. 실패해도 말하지 않는다.
  PROCEDURE try_q(p_sql IN VARCHAR2) IS
  BEGIN
    EXECUTE IMMEDIATE p_sql;
    DBMS_OUTPUT.PUT_LINE('  지움: ' || p_sql);
  EXCEPTION
    WHEN OTHERS THEN
      NULL;
  END try_q;

  -- 계정을 지운다. 접속 중인 세션이 있으면 지워지지 않으므로(ORA-01940) 먼저 계정을
  -- 잠가 새 접속을 막고, 접속 중인 세션을 끊은 뒤 지운다. 키 저장소 유지 프로그램이
  -- 이 계정으로 계속 다시 접속하는 경우에도 잠겨 있으므로 접속하지 못한다.
  PROCEDURE drop_user(p_user IN VARCHAR2) IS
    v_n  NUMBER;
    v_ok BOOLEAN := FALSE;
  BEGIN
    SELECT COUNT(*) INTO v_n FROM dba_users WHERE username = p_user;
    IF v_n = 0 THEN
      DBMS_OUTPUT.PUT_LINE('  없음: ' || p_user);
      RETURN;
    END IF;

    try('ALTER USER ' || p_user || ' ACCOUNT LOCK');
    FOR attempt IN 1 .. 3 LOOP
      FOR s IN (SELECT sid, serial# FROM v$session WHERE username = p_user) LOOP
        try('ALTER SYSTEM KILL SESSION ''' || s.sid || ',' || s.serial# || ''' IMMEDIATE');
      END LOOP;
      DBMS_SESSION.SLEEP(2);
      v_ok := try_b('DROP USER ' || p_user || ' CASCADE');
      EXIT WHEN v_ok;
    END LOOP;
  END drop_user;
BEGIN
  IF v_ok <> 'DROP' THEN
    DBMS_OUTPUT.PUT_LINE('취소하였다. 아무것도 지우지 않았다.');
    RETURN;
  END IF;

  -- 업무 계정(응용 스키마)의 예시 객체와 실제 업무 객체는 건드리지 않는다. 예시는
  -- 해당 계정에서 08_sample/890_drop_samples.sql 로 지운다.

  -- 통합 감사 정책(310_lockdown.sql 이 만든 것). 정책은 계정과 별개로 남으므로 계정보다
  -- 먼저 끄고 지운다. 남겨 두면 다시 설치할 때 310 이 「이미 있다」로 실패한다.
  -- 정책이 가리키던 표가 먼저 사라져 감사 옵션이 없는 빈 정책은 조회 뷰에 나오지 않으므로
  -- 이름을 직접 적어 지운다.
  FOR p IN (SELECT column_value AS policy_name FROM TABLE(SYS.ODCIVARCHAR2LIST(
              'OCS_POL_OWNER_ACCESS', 'OCS_POL_DDL', 'OCS_POL_KEY_TABLE', 'OCS_POL_PRIV_CHANGE'))) LOOP
    try_q('NOAUDIT POLICY ' || p.policy_name);
    try_q('DROP AUDIT POLICY ' || p.policy_name);
  END LOOP;

  -- 문맥은 계정보다 먼저 지운다.
  FOR c IN (SELECT namespace FROM dba_context WHERE namespace LIKE 'OCS\_%' ESCAPE '\') LOOP
    try('DROP CONTEXT ' || c.namespace);
  END LOOP;

  -- 다른 스키마에 만든 FN_ 시노님(480_connect_app_schema.sql)은 대상이 사라지면 깨진 채
  -- 남으므로 먼저 지운다.
  FOR s IN (SELECT owner, synonym_name FROM dba_synonyms
             WHERE table_owner = 'OCS_OWNER' AND owner <> 'OCS_OWNER') LOOP
    IF s.owner = 'PUBLIC' THEN
      try('DROP PUBLIC SYNONYM ' || s.synonym_name);
    ELSE
      try('DROP SYNONYM ' || s.owner || '.' || s.synonym_name);
    END IF;
  END LOOP;

  -- 계정을 통째로 지우면 그 안의 표(SEC_CONFIG 등)와 패키지와 키가 함께 사라진다.
  drop_user('OCS_OWNER');
  drop_user('OCS_KEYADM');
  drop_user('OCS_AUDITOR');

  FOR r IN (SELECT role FROM dba_roles WHERE role IN
              ('OCS_ROLE_APP', 'OCS_ROLE_KEYADM', 'OCS_ROLE_AUDITOR')) LOOP
    try('DROP ROLE ' || r.role);
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('');
  DBMS_OUTPUT.PUT_LINE('제거를 마쳤다. 아래 조회가 모두 비어 있어야 한다.');
END;
/

SET DEFINE OFF

PROMPT
PROMPT === 남은 계정 (비어 있어야 정상) ===
SELECT username FROM dba_users WHERE username LIKE 'OCS%';

PROMPT
PROMPT === 남은 역할 (비어 있어야 정상) ===
SELECT role FROM dba_roles WHERE role LIKE 'OCS%';

PROMPT
PROMPT === 남은 문맥 (비어 있어야 정상) ===
SELECT namespace FROM dba_context WHERE namespace LIKE 'OCS%';

PROMPT
PROMPT === 남은 통합 감사 정책 (비어 있어야 정상) ===
SELECT DISTINCT policy_name FROM audit_unified_policies WHERE policy_name LIKE 'OCS%';

PROMPT
PROMPT === 남은 시노님 (비어 있어야 정상) ===
SELECT owner, synonym_name FROM dba_synonyms WHERE table_owner = 'OCS_OWNER';

PROMPT
PROMPT 위 다섯 조회가 모두 비어 있으면 설치 전 상태다. 위쪽에 [실패] 가 있으면 그 이유를
PROMPT 먼저 풀고 이 스크립트를 다시 실행한다. 다시 실행해도 안전하다.
PROMPT
PROMPT 데이터베이스 밖에 남는 것은 이 스크립트가 지우지 않는다. 키 저장소 유지 프로그램
PROMPT (작업 스케줄러 작업이나 systemd 서비스)과 keeper.properties 의 마스터 키는 재설치
PROMPT 전에 따로 멈추거나 새 설치에 맞게 고친다. 업무 계정 쪽의 예시 객체는 08_sample/
PROMPT 890_drop_samples.sql 로 지운다. 설치 매뉴얼의 설치 진행 장(윈도우 개발·시험은 제3장, 운영은 제7장)부터 다시 시작하면 된다.

SET FEEDBACK ON
