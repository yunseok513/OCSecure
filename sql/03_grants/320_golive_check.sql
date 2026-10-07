-- 운영 개통 판정
-- SYS 또는 그에 준하는 권한으로, 대상 PDB 에서 실행한다. 아무것도 바꾸지 않는다.
--
-- 310_lockdown.sql 은 개발과 시험 설치도 잠글 수 있도록 설정이 위험해도 끝까지
-- 진행한다. 이 스크립트는 그와 분리하여, 운영 개통에 필요한 조건이 모두 갖추어졌는지
-- 판정하고 하나라도 어긋나면 오류로 끝낸다. 개통 승인은 이 스크립트가 통과한 뒤에만 한다.
--
-- 개발과 시험 설치(KEK_SOURCE=GLOBAL_CTX)에서는 불가로 끝나는 것이 정상이다.
-- KEK_SOURCE=SCOPED_CTX 는 위험 수용 기록(KEK_RISK_ACK)이 있을 때만 통과한다.

WHENEVER SQLERROR EXIT SQL.SQLCODE
SET SERVEROUTPUT ON SIZE 100000

DECLARE
  v_fail  PLS_INTEGER := 0;
  v_val   VARCHAR2(200);
  v_n     NUMBER;
  v_st    VARCHAR2(30);

  PROCEDURE chk(p_name IN VARCHAR2, p_ok IN BOOLEAN, p_detail IN VARCHAR2) IS
  BEGIN
    DBMS_OUTPUT.PUT_LINE(RPAD(p_name, 36) || CASE WHEN p_ok THEN '통과  ' ELSE '불가  ' END
                         || p_detail);
    IF NOT p_ok THEN
      v_fail := v_fail + 1;
    END IF;
  END chk;
BEGIN
  DBMS_OUTPUT.PUT_LINE('=== 운영 개통 판정 ===');

  SELECT cfg_value INTO v_val FROM OCS_OWNER.SEC_CONFIG WHERE cfg_key = 'KEK_SOURCE';
  IF v_val = 'SCOPED_CTX' THEN
    -- 외부 키 관리 서버를 쓸 수 없는 운영용. 남는 위험을 수용했다는 기록이 있어야 한다.
    SELECT COUNT(*) INTO v_n FROM OCS_OWNER.SEC_CONFIG WHERE cfg_key = 'KEK_RISK_ACK';
    chk('마스터 키 반입 방식', v_n = 1,
        'KEK_SOURCE=SCOPED_CTX, 위험 수용 기록 ' || CASE WHEN v_n = 1 THEN '있음' ELSE '없음(490_kek_risk_ack.sql)' END);
  ELSE
    chk('마스터 키 반입 방식', v_val = 'EXTERNAL', 'KEK_SOURCE=' || v_val);
  END IF;

  SELECT cfg_value INTO v_val FROM OCS_OWNER.SEC_CONFIG WHERE cfg_key = 'APPCTX_MODE';
  chk('응용 문맥 증표 검증', v_val = 'PROOF', 'APPCTX_MODE=' || v_val);

  SELECT account_status INTO v_st FROM dba_users WHERE username = 'OCS_OWNER';
  chk('소유 계정 잠금', v_st LIKE 'LOCKED%', 'OCS_OWNER ' || v_st);

  SELECT COUNT(*) INTO v_n FROM audit_unified_enabled_policies
   WHERE policy_name IN ('OCS_POL_OWNER_ACCESS', 'OCS_POL_DDL',
                         'OCS_POL_KEY_TABLE', 'OCS_POL_PRIV_CHANGE');
  chk('감사 정책 네 개', v_n = 4, v_n || '개 켜져 있음');

  SELECT COUNT(*) INTO v_n FROM dba_tables
   WHERE owner = 'OCS_OWNER' AND table_name = 'SEC_KAT';
  chk('시험용 표 SEC_KAT 제거', v_n = 0, v_n || '개 남아 있음');

  SELECT COUNT(*) INTO v_n FROM dba_tab_comments
   WHERE comments = 'OCSecure sample' AND owner NOT IN ('SYS', 'SYSTEM');
  chk('예시 표와 뷰 제거', v_n = 0, v_n || '개 남아 있음');

  IF v_fail > 0 THEN
    DBMS_OUTPUT.PUT_LINE('=== 운영 개통 불가: ' || v_fail || '개 항목 ===');
    RAISE_APPLICATION_ERROR(-20999, '운영 개통 조건을 갖추지 못했다');
  END IF;
  DBMS_OUTPUT.PUT_LINE('=== 운영 개통 조건 충족. 데이터베이스 밖의 일(매뉴얼 4.6.3)은 따로 확인할 것 ===');
END;
/
