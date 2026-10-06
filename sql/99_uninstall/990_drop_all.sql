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
-- 업무 스키마의 표는 지우지 않는다. 08_sample 로 만든 예시 표는 제거 대상에
-- 포함되나, 실제 업무 표는 사람이 판단해야 할 일이므로 건드리지 않는다.

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

  PROCEDURE try(p_sql IN VARCHAR2) IS
  BEGIN
    EXECUTE IMMEDIATE p_sql;
    DBMS_OUTPUT.PUT_LINE('  지움: ' || p_sql);
  EXCEPTION
    WHEN OTHERS THEN
      -- 없는 것을 지우려 한 경우가 대부분이다. 처음부터 다시 돌릴 수 있어야 하므로
      -- 실패를 멈춤 사유로 보지 않는다.
      DBMS_OUTPUT.PUT_LINE('  건너뜀: ' || p_sql || '  (' || SQLCODE || ')');
  END try;
BEGIN
  IF v_ok <> 'DROP' THEN
    DBMS_OUTPUT.PUT_LINE('취소하였다. 아무것도 지우지 않았다.');
    RETURN;
  END IF;

  -- 예시 스키마의 표와 뷰. 실제 업무 표는 건드리지 않는다.
  try('DROP TABLE OCS_APP.TB_MEMBER_ENC CASCADE CONSTRAINTS PURGE');
  try('DROP VIEW  OCS_APP.TB_MEMBER');

  -- 문맥은 계정보다 먼저 지운다.
  try('DROP CONTEXT OCS_APP_CTX');
  try('DROP CONTEXT OCS_KEK_CTX');

  -- 계정을 통째로 지우면 그 안의 표와 패키지와 키가 함께 사라진다.
  try('DROP USER OCS_OWNER CASCADE');
  try('DROP USER OCS_KEYADM CASCADE');
  try('DROP USER OCS_AUDITOR CASCADE');
  try('DROP USER OCS_APP CASCADE');

  try('DROP ROLE OCS_ROLE_APP');
  try('DROP ROLE OCS_ROLE_KEYADM');
  try('DROP ROLE OCS_ROLE_AUDITOR');

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
PROMPT 셋 다 비어 있으면 설치 전 상태다. 설치 매뉴얼 제3장부터 다시 시작하면 된다.

SET FEEDBACK ON
