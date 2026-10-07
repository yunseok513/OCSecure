-- 마스터 키 반입 방식의 잔여 위험 수용 기록
-- SYS 로 대상 PDB 에서 실행한다. KEK_SOURCE 가 SCOPED_CTX 일 때만 의미가 있다.
--
-- SCOPED_CTX 는 외부 키 관리 서버나 하드웨어 보안 모듈 없이 쓰는 운영용 방식이다.
-- 응용 계정이 마스터 키를 읽는 것은 막지만 아래는 막지 못한다. 이를 알고도 쓰기로
-- 했다는 책임자의 확인을 기록해야 320_golive_check.sql 이 통과한다.
--
--   - SYS 와 OCS_OWNER 를 쥔 사람이 키를 꺼내 쓰는 것
--   - 키 유지 프로그램이 있는 장비의 관리자가 설정 파일이나 메모리에서 키를 얻는 것
--
-- 이 스크립트는 기록만 남기며 다른 설정을 바꾸지 않는다. 기록은 승인자, 날짜,
-- 문서 번호를 한 줄로 합친 것이다. 기록은 감사 담당자가 확인할 수 있어야 하므로
-- 문서 번호를 정확히 적을 것.

SET SERVEROUTPUT ON
SET DEFINE ON
SET VERIFY OFF

PROMPT
PROMPT === 마스터 키 잔여 위험 수용 기록 ===
SELECT cfg_value AS kek_source FROM OCS_OWNER.SEC_CONFIG WHERE cfg_key = 'KEK_SOURCE';
PROMPT
PROMPT KEK_SOURCE 가 SCOPED_CTX 가 아니면 이 기록은 필요하지 않다. Ctrl+C 로 멈출 것.
PROMPT

ACCEPT who CHAR PROMPT '  승인자(성명과 직책): '
ACCEPT doc CHAR PROMPT '  승인 문서 번호: '

DECLARE
  v_text VARCHAR2(200);
BEGIN
  v_text := SUBSTR('&who | &doc | ' || TO_CHAR(SYSDATE, 'YYYY-MM-DD'), 1, 200);
  MERGE INTO OCS_OWNER.SEC_CONFIG c
  USING (SELECT 'KEK_RISK_ACK' AS k FROM DUAL) s ON (c.cfg_key = s.k)
  WHEN MATCHED THEN UPDATE SET cfg_value = v_text, updated_at = SYSTIMESTAMP
  WHEN NOT MATCHED THEN INSERT (cfg_key, cfg_value, description)
    VALUES (s.k, v_text, '마스터 키 반입 방식(SCOPED_CTX)의 잔여 위험을 수용했다는 확인 기록');
  COMMIT;
  DBMS_OUTPUT.PUT_LINE('  기록했다: ' || v_text);
END;
/

UNDEFINE who doc
SET DEFINE OFF
