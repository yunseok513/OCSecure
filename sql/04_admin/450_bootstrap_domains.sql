-- 운영 도메인과 키 등록
-- OCS_KEYADM 계정으로 실행한다. OCS_OWNER 로는 실행되지 않는다.
--
-- 권한이 계정으로 갈리는 것이 설계 의도다. 스키마를 소유한 계정과 키를 만드는
-- 계정을 나누어 두어야, 한 계정이 새더라도 혼자서는 자료를 풀 수 없다.
--
-- 실행 전에 두 가지가 되어 있어야 한다.
--   하나, OCS_OWNER 가 SEC_CONFIG 의 KEK_SOURCE 를 정해 두었을 것.
--   둘,   마스터 키가 주입되어 있을 것 (GLOBAL_CTX 모드인 경우).
--
-- 이 스크립트는 여러 번 실행해도 안전하다. 도메인은 있으면 갱신하고, 키는
-- 활성 키가 이미 있으면 새로 만들지 않는다.

SET SERVEROUTPUT ON SIZE 100000
SET FEEDBACK OFF

PROMPT === 1. 도메인 등록 ===
BEGIN
  -- 주민등록번호. 구분자가 있든 없든 같은 값으로 보도록 숫자만 남긴다.
  -- 복호화는 애플리케이션 문맥이 있을 때만 허용하고, 한 구간에 200건을 넘기면 막는다.
  OCS_OWNER.PKG_KEY_ADMIN.upsert_domain(
    'RRN', '주민등록번호', 'DIGITS', 'RRN', 'Y', 200, 'SUMMARY');

  -- 성명. 앞뒤 공백만 정리한다. 한 사람이 많이 볼 수 있는 항목이라 임계치를 두지 않는다.
  OCS_OWNER.PKG_KEY_ADMIN.upsert_domain(
    'NAME', '성명', 'TRIM', 'NAME', 'Y', 0, 'SUMMARY');

  -- 연락처. 숫자만 남겨 하이픈 유무를 흡수한다.
  OCS_OWNER.PKG_KEY_ADMIN.upsert_domain(
    'PHONE', '연락처', 'DIGITS', 'PHONE', 'Y', 0, 'SUMMARY');

  -- 계좌번호. 금전과 직결되므로 모든 복호화를 개별 기록한다.
  OCS_OWNER.PKG_KEY_ADMIN.upsert_domain(
    'ACCOUNT', '계좌번호', 'DIGITS', 'ACCOUNT', 'Y', 50, 'FULL');
  COMMIT;
  DBMS_OUTPUT.PUT_LINE('  도메인 4건 등록 완료');
END;
/

PROMPT
PROMPT === 2. 도메인별 운영 키 생성 ===
DECLARE
  v_id  PLS_INTEGER;
  v_cnt PLS_INTEGER;
  TYPE t_doms IS TABLE OF VARCHAR2(30);
  v_doms t_doms := t_doms('RRN', 'NAME', 'PHONE', 'ACCOUNT');
BEGIN
  FOR i IN 1 .. v_doms.COUNT LOOP
    SELECT COUNT(*) INTO v_cnt FROM OCS_OWNER.V_SEC_KEY_STATUS
     WHERE domain_code = v_doms(i) AND key_state = 'ACTIVE';

    IF v_cnt > 0 THEN
      DBMS_OUTPUT.PUT_LINE('  ' || RPAD(v_doms(i), 10) || ' 활성 키가 이미 있다. 건너뛴다.');
    ELSE
      v_id := OCS_OWNER.PKG_KEY_ADMIN.create_key(v_doms(i), TRUE, '개통 초기 키');
      DBMS_OUTPUT.PUT_LINE('  ' || RPAD(v_doms(i), 10) || ' 키 생성 및 활성, key_id=' || v_id);
    END IF;
  END LOOP;
  COMMIT;
END;
/

PROMPT
PROMPT === 3. 확인 ===
SELECT domain_code, key_id, key_state, alg_id FROM OCS_OWNER.V_SEC_KEY_STATUS
 ORDER BY domain_code, key_id;

PROMPT
PROMPT 도메인 4건에 각각 ACTIVE 키가 하나씩 있어야 한다.
PROMPT
PROMPT 여기까지로는 아직 쓸 수 없다. 위 도메인들이 애플리케이션 인증 문맥을
PROMPT 요구하므로, 460_appctx_key.sql 로 증표용 키를 등록해야 한다.

SET FEEDBACK ON
