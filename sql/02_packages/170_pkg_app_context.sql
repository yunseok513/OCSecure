-- 애플리케이션 인증 문맥
--
-- 응용 계정의 접속 정보를 알아낸 사람이 조회 도구로 직접 접속하더라도 복호화가
-- 되지 않게 하는 장치다. 정책 계층은 이 문맥이 설정된 세션에서만 복호화를 허용한다.
--
-- 다만 문맥을 설정하는 절차 자체가 누구에게나 열려 있으면 통제가 성립하지 않는다.
-- 응용 계정으로 접속한 사람이 이 프로시저를 그냥 호출해 버리면 그만이기 때문이다.
-- 그래서 두 가지 방식을 둔다.
--
--   PROOF   운영용. 애플리케이션 계층이 보유한 비밀 키로 계산한 증표를 함께
--           제출해야 한다. 그 키는 데이터베이스 밖에 있으므로 데이터베이스
--           접속 정보만 가진 사람은 증표를 만들 수 없다. 증표에 세션 식별자와
--           시각을 묶어 가로챈 증표의 재사용도 막는다.
--
--   SIMPLE  개발과 시험용. 증표 없이 문맥을 설정한다. 운영계에서 쓰면 이 통제는
--           사실상 없는 것과 같다.
--
-- PROOF 방식의 비밀 키는 SEC_KEY 의 '_APPCTX' 도메인에 감싸여 보관되며, 같은 값을
-- 애플리케이션 서버가 자신의 설정에 보관한다. 이 키의 배포와 교체는 키 관리자가 맡는다.

CREATE OR REPLACE PACKAGE PKG_APP_CONTEXT AS
  c_domain CONSTANT VARCHAR2(30) := '_APPCTX';

  -- p_proof = HMAC-SHA256(appctx_key, 응용사용자 || '|' || p_epoch || '|' || 세션식별자)
  PROCEDURE set_identity(p_app_user IN VARCHAR2,
                         p_epoch    IN NUMBER DEFAULT NULL,
                         p_proof    IN RAW    DEFAULT NULL);

  PROCEDURE clear_identity;

  FUNCTION app_user       RETURN VARCHAR2;
  FUNCTION is_established RETURN BOOLEAN;

  -- 애플리케이션 계층이 증표를 만들 때 쓰는 것과 같은 규칙으로 기대값을 계산한다.
  -- 연동 시험용으로 공개하며, 키 자체는 반환하지 않는다.
  FUNCTION expected_proof(p_app_user IN VARCHAR2,
                          p_epoch    IN NUMBER,
                          p_sid      IN NUMBER) RETURN RAW;
END PKG_APP_CONTEXT;
/

CREATE OR REPLACE PACKAGE BODY PKG_APP_CONTEXT AS

  FUNCTION cfg(p_key VARCHAR2, p_default VARCHAR2) RETURN VARCHAR2 IS
    v VARCHAR2(200);
  BEGIN
    SELECT cfg_value INTO v FROM SEC_CONFIG WHERE cfg_key = p_key;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN p_default;
  END cfg;

  FUNCTION epoch_now RETURN NUMBER IS
  BEGIN
    RETURN (CAST(SYS_EXTRACT_UTC(SYSTIMESTAMP) AS DATE)
              - TO_DATE('1970-01-01', 'YYYY-MM-DD')) * 86400;
  END epoch_now;

  FUNCTION expected_proof(p_app_user IN VARCHAR2,
                          p_epoch    IN NUMBER,
                          p_sid      IN NUMBER) RETURN RAW IS
    v_key PKG_KEY_STORE.t_keyset;
    v_msg VARCHAR2(400);
  BEGIN
    v_key := PKG_KEY_STORE.get_active(c_domain);
    v_msg := p_app_user || '|' || TO_CHAR(p_epoch) || '|' || TO_CHAR(p_sid);
    RETURN PKG_PROVIDER_DBMS.mac(UTL_I18N.STRING_TO_RAW(v_msg, 'AL32UTF8'), v_key.idx_key);
  END expected_proof;

  PROCEDURE set_identity(p_app_user IN VARCHAR2,
                         p_epoch    IN NUMBER DEFAULT NULL,
                         p_proof    IN RAW    DEFAULT NULL) IS
    v_mode   VARCHAR2(20) := cfg('APPCTX_MODE', 'PROOF');
    v_window NUMBER       := TO_NUMBER(cfg('APPCTX_WINDOW_SEC', '300'));
    v_sid    NUMBER       := SYS_CONTEXT('USERENV', 'SID');
  BEGIN
    IF p_app_user IS NULL THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '응용 사용자 식별자가 비어 있음');
    END IF;

    IF v_mode = 'PROOF' THEN
      IF p_epoch IS NULL OR p_proof IS NULL THEN
        PKG_AUDIT.log('APPCTX_DENIED', 'ALERT', NULL, '증표 없음');
        PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_app_ctx, '증표가 제출되지 않음');
      END IF;

      -- 오래된 증표를 거부하여 재사용을 막는다. 세션 식별자까지 묶여 있으므로
      -- 다른 세션에서 가로챈 증표를 그대로 쓸 수도 없다.
      IF ABS(epoch_now - p_epoch) > v_window THEN
        PKG_AUDIT.log('APPCTX_DENIED', 'ALERT', NULL, '증표 유효 시간 초과');
        PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_app_ctx, '증표 유효 시간 초과');
      END IF;

      IF NOT PKG_CRYPTO_FMT.const_eq(expected_proof(p_app_user, p_epoch, v_sid), p_proof) THEN
        PKG_AUDIT.log('APPCTX_DENIED', 'ALERT', NULL,
                      '증표 불일치 (응용 사용자: ' || SUBSTR(p_app_user, 1, 60) || ')');
        PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_app_ctx, '증표 불일치');
      END IF;

    ELSIF v_mode <> 'SIMPLE' THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config, 'APPCTX_MODE 설정값 오류: ' || v_mode);
    END IF;

    DBMS_SESSION.SET_CONTEXT('OCS_APP_CTX', 'APP_USER', p_app_user);
    DBMS_SESSION.SET_CONTEXT('OCS_APP_CTX', 'ESTABLISHED_AT',
                             TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'));
  END set_identity;

  PROCEDURE clear_identity IS
  BEGIN
    DBMS_SESSION.CLEAR_CONTEXT('OCS_APP_CTX');
  END clear_identity;

  FUNCTION app_user RETURN VARCHAR2 IS
  BEGIN
    RETURN SYS_CONTEXT('OCS_APP_CTX', 'APP_USER');
  END app_user;

  FUNCTION is_established RETURN BOOLEAN IS
  BEGIN
    RETURN SYS_CONTEXT('OCS_APP_CTX', 'APP_USER') IS NOT NULL;
  END is_established;

END PKG_APP_CONTEXT;
/
