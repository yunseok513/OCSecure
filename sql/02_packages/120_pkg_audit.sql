-- 감사 기록
--
-- 자율 트랜잭션으로 기록하므로 업무 트랜잭션이 되돌려져도 감사 기록은 남는다.
-- 복호화 시도가 있었다는 사실은 그 시도가 실패하거나 취소되어도 남아야 한다.
--
-- 이 패키지는 평문과 키와 암호문 전체를 기록하지 않는다. 감사 로그는 상대적으로
-- 접근 통제가 느슨하게 관리되는 경우가 많아, 여기에 값이 남으면 암호화 전체가
-- 무의미해진다. 코드 검토의 필수 점검 항목이다.

CREATE OR REPLACE PACKAGE PKG_AUDIT AS
  PROCEDURE log(p_event_type  IN VARCHAR2,
                p_severity    IN VARCHAR2 DEFAULT 'INFO',
                p_domain_code IN VARCHAR2 DEFAULT NULL,
                p_detail      IN VARCHAR2 DEFAULT NULL,
                p_cnt         IN NUMBER   DEFAULT NULL);

  -- 복호화 사용량 집계. 전건 기록 대신 구간별 누계를 남겨 기록량을 억제한다.
  PROCEDURE bump_usage(p_domain_code IN VARCHAR2,
                       p_reveal      IN NUMBER DEFAULT 0,
                       p_denied      IN NUMBER DEFAULT 0);

  FUNCTION usage_in_bucket(p_domain_code IN VARCHAR2) RETURN NUMBER;
  FUNCTION bucket_of(p_ts IN DATE DEFAULT SYSDATE) RETURN DATE;
END PKG_AUDIT;
/

CREATE OR REPLACE PACKAGE BODY PKG_AUDIT AS

  FUNCTION cfg_num(p_key VARCHAR2, p_default NUMBER) RETURN NUMBER IS
    v NUMBER;
  BEGIN
    SELECT TO_NUMBER(cfg_value) INTO v FROM SEC_CONFIG WHERE cfg_key = p_key;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN p_default;
    WHEN VALUE_ERROR   THEN RETURN p_default;
  END cfg_num;

  FUNCTION bucket_of(p_ts IN DATE DEFAULT SYSDATE) RETURN DATE IS
    v_min NUMBER := cfg_num('USAGE_BUCKET_MIN', 60);
  BEGIN
    IF v_min <= 0 THEN
      v_min := 60;
    END IF;
    -- 구간 시작 시각으로 절삭한다.
    RETURN TRUNC(p_ts) + FLOOR((p_ts - TRUNC(p_ts)) * 1440 / v_min) * v_min / 1440;
  END bucket_of;

  PROCEDURE log(p_event_type  IN VARCHAR2,
                p_severity    IN VARCHAR2 DEFAULT 'INFO',
                p_domain_code IN VARCHAR2 DEFAULT NULL,
                p_detail      IN VARCHAR2 DEFAULT NULL,
                p_cnt         IN NUMBER   DEFAULT NULL) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
  BEGIN
    INSERT INTO SEC_AUDIT_LOG (
      event_type, severity, domain_code, db_user, os_user, host_name,
      ip_address, module_name, session_id, app_user, affected_cnt, detail)
    VALUES (
      p_event_type,
      p_severity,
      p_domain_code,
      SYS_CONTEXT('USERENV', 'SESSION_USER'),
      SYS_CONTEXT('USERENV', 'OS_USER'),
      SYS_CONTEXT('USERENV', 'HOST'),
      SYS_CONTEXT('USERENV', 'IP_ADDRESS'),
      SYS_CONTEXT('USERENV', 'MODULE'),
      SYS_CONTEXT('USERENV', 'SID'),
      SYS_CONTEXT('OCS_APP_CTX', 'APP_USER'),
      p_cnt,
      SUBSTR(p_detail, 1, 400));
    COMMIT;
  EXCEPTION
    WHEN OTHERS THEN
      -- 감사 기록 실패가 업무를 중단시키지 않게 한다. 다만 조용히 넘기지 않고
      -- 경보 채널로 올릴 수 있도록 서버 출력에 남긴다.
      ROLLBACK;
      DBMS_OUTPUT.PUT_LINE('OCSecure 감사 기록 실패: ' || SQLERRM);
  END log;

  PROCEDURE bump_usage(p_domain_code IN VARCHAR2,
                       p_reveal      IN NUMBER DEFAULT 0,
                       p_denied      IN NUMBER DEFAULT 0) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
    v_user VARCHAR2(128) := SYS_CONTEXT('USERENV', 'SESSION_USER');
    v_b    DATE          := bucket_of;
  BEGIN
    MERGE INTO SEC_REVEAL_USAGE t
    USING (SELECT v_user AS db_user, p_domain_code AS domain_code, v_b AS bucket_ts
             FROM DUAL) s
    ON (t.db_user = s.db_user AND t.domain_code = s.domain_code AND t.bucket_ts = s.bucket_ts)
    WHEN MATCHED THEN
      UPDATE SET t.reveal_cnt = t.reveal_cnt + p_reveal,
                 t.denied_cnt = t.denied_cnt + p_denied,
                 t.updated_at = SYSTIMESTAMP
    WHEN NOT MATCHED THEN
      INSERT (db_user, domain_code, bucket_ts, reveal_cnt, denied_cnt)
      VALUES (s.db_user, s.domain_code, s.bucket_ts, p_reveal, p_denied);
    COMMIT;
  EXCEPTION
    WHEN OTHERS THEN
      ROLLBACK;
      DBMS_OUTPUT.PUT_LINE('OCSecure 사용량 집계 실패: ' || SQLERRM);
  END bump_usage;

  FUNCTION usage_in_bucket(p_domain_code IN VARCHAR2) RETURN NUMBER IS
    v NUMBER;
  BEGIN
    SELECT reveal_cnt INTO v
      FROM SEC_REVEAL_USAGE
     WHERE db_user     = SYS_CONTEXT('USERENV', 'SESSION_USER')
       AND domain_code = p_domain_code
       AND bucket_ts   = bucket_of;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN 0;
  END usage_in_bucket;

END PKG_AUDIT;
/
