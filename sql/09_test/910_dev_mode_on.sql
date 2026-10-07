-- 개발·시험 전용 빠른 경로 켜기
-- SYS 로, 대상 PDB 에서 실행한다. **운영 인스턴스에서는 절대 실행하지 말 것.**
--
-- 응용 문맥 모드를 SIMPLE 로 바꾼다. 이 모드에서는 증표 검증이 없어서, 증표 키 없이
-- 응용 문맥을 세울 수 있다. 그래서 SQL*Plus 에서도 PKG_SECURE_API.login('사용자')
-- 한 줄로 문맥이 서고 FN_ENC_... 같은 함수를 바로 시험해 볼 수 있다.
--
-- 위험. SIMPLE 에서는 접속 정보만으로 암호화와 복호화가 된다. 개발·시험 인스턴스에서
-- 실제 개인정보 없이 쓸 때만 켜고, 끝나면 911_dev_mode_off.sql 로 반드시 되돌린다.
-- 켜 둔 채로는 운영 개통 판정(03_grants/320_golive_check.sql)이 「불가」로 나온다.
-- 설정 변경은 통합 감사 정책이 켜져 있으면 기록된다.

SET SERVEROUTPUT ON
SET VERIFY OFF
SET DEFINE ON

PROMPT
PROMPT === 지금 접속한 곳 ===
SELECT SYS_CONTEXT('USERENV','CON_NAME')     AS 컨테이너,
       SYS_CONTEXT('USERENV','SESSION_USER') AS 접속계정
  FROM dual;

PROMPT
PROMPT === 지금 설정 ===
SELECT cfg_key, cfg_value FROM OCS_OWNER.SEC_CONFIG
 WHERE cfg_key IN ('APPCTX_MODE', 'KEK_SOURCE') ORDER BY cfg_key;

PROMPT
PROMPT 개발·시험 인스턴스가 맞고 실제 개인정보가 없을 때만 진행한다.
ACCEPT ok CHAR PROMPT '  증표 검증을 끄려면 DEV 라고 입력하시오: '

DECLARE
  v_ok VARCHAR2(20) := '&ok';
BEGIN
  IF v_ok <> 'DEV' THEN
    DBMS_OUTPUT.PUT_LINE('취소하였다. 아무것도 바꾸지 않았다.');
    RETURN;
  END IF;
  IF SYS_CONTEXT('USERENV', 'SESSION_USER') <> 'SYS' THEN
    DBMS_OUTPUT.PUT_LINE('SYS 로 접속하여 실행하십시오. 아무것도 바꾸지 않았다.');
    RETURN;
  END IF;
  IF SYS_CONTEXT('USERENV', 'CON_NAME') = 'CDB$ROOT' THEN
    DBMS_OUTPUT.PUT_LINE('컨테이너 최상위입니다. 대상 PDB 로 옮긴 뒤 실행하십시오. 아무것도 바꾸지 않았다.');
    RETURN;
  END IF;

  UPDATE OCS_OWNER.SEC_CONFIG SET cfg_value = 'SIMPLE', updated_at = SYSTIMESTAMP
   WHERE cfg_key = 'APPCTX_MODE';
  COMMIT;
  DBMS_OUTPUT.PUT_LINE('APPCTX_MODE = SIMPLE (개발 모드 켬). 시험이 끝나면 911_dev_mode_off.sql 로 되돌릴 것.');
END;
/

UNDEFINE ok
