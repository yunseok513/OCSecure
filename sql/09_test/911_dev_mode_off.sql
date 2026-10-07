-- 개발·시험 전용 빠른 경로 끄기
-- SYS 로, 대상 PDB 에서 실행한다. 910_dev_mode_on.sql 로 켠 것을 운영 설정으로 되돌린다.
-- 응용 문맥 모드를 PROOF(증표 검증)로 되돌린다. 여러 번 실행해도 안전하다.

SET SERVEROUTPUT ON
SET VERIFY OFF

DECLARE
BEGIN
  IF SYS_CONTEXT('USERENV', 'SESSION_USER') <> 'SYS' THEN
    DBMS_OUTPUT.PUT_LINE('SYS 로 접속하여 실행하십시오. 아무것도 바꾸지 않았다.');
    RETURN;
  END IF;
  IF SYS_CONTEXT('USERENV', 'CON_NAME') = 'CDB$ROOT' THEN
    DBMS_OUTPUT.PUT_LINE('컨테이너 최상위입니다. 대상 PDB 로 옮긴 뒤 실행하십시오. 아무것도 바꾸지 않았다.');
    RETURN;
  END IF;

  UPDATE OCS_OWNER.SEC_CONFIG SET cfg_value = 'PROOF', updated_at = SYSTIMESTAMP
   WHERE cfg_key = 'APPCTX_MODE';
  COMMIT;
  DBMS_OUTPUT.PUT_LINE('APPCTX_MODE = PROOF (운영 설정으로 되돌림).');
END;
/

PROMPT
PROMPT === 지금 설정 (APPCTX_MODE 는 PROOF 여야 한다) ===
SELECT cfg_key, cfg_value FROM OCS_OWNER.SEC_CONFIG
 WHERE cfg_key IN ('APPCTX_MODE', 'KEK_SOURCE') ORDER BY cfg_key;
