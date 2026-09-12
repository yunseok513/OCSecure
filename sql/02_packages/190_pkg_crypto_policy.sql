-- 정책 계층
--
-- 복호화 요청이 이 계층을 우회할 수 없어야 한다는 것이 이 설계의 핵심이다.
-- 우회 차단은 아래 계층(PKG_CRYPTO_CORE 등)에 어떤 계정에도 실행 권한을 주지
-- 않음으로써 달성한다. 그 권한이 새어 나가는 순간 이 계층의 모든 판정은
-- 의미를 잃으므로, 권한 점검의 최우선 항목이다.
--
-- 판정 순서는 문맥, 권한, 사용량이다. 거부된 요청도 기록한다. 거부 기록이 쌓이는
-- 양상이 침해 시도를 가장 먼저 드러내는 신호인 경우가 많다.

CREATE OR REPLACE PACKAGE PKG_CRYPTO_POLICY AS

  FUNCTION protect (p_domain_code IN VARCHAR2, p_plain  IN VARCHAR2) RETURN RAW;
  FUNCTION index_of(p_domain_code IN VARCHAR2, p_plain  IN VARCHAR2) RETURN RAW;

  -- 평문을 돌려준다. 자격이 없으면 예외를 낸다.
  FUNCTION reveal(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2;

  -- 자격이 있으면 평문을, 없으면 마스킹된 값을 돌려준다. 목록 화면에서 쓴다.
  FUNCTION reveal_or_mask(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2;

  -- 자격과 무관하게 항상 마스킹된 값을 돌려준다.
  FUNCTION mask(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2;

  FUNCTION mask_value(p_mask_type IN VARCHAR2, p_plain IN VARCHAR2) RETURN VARCHAR2;

  FUNCTION can_reveal(p_domain_code IN VARCHAR2) RETURN VARCHAR2;  -- 'Y' 또는 'N'
END PKG_CRYPTO_POLICY;
/

CREATE OR REPLACE PACKAGE BODY PKG_CRYPTO_POLICY AS

  TYPE t_domain IS RECORD (
    norm_mode       VARCHAR2(12),
    mask_type       VARCHAR2(20),
    require_app_ctx CHAR(1),
    reveal_limit    NUMBER,
    audit_level     VARCHAR2(10));

  TYPE t_domain_cache IS TABLE OF t_domain INDEX BY VARCHAR2(30);
  g_domains t_domain_cache;

  FUNCTION cfg_num(p_key VARCHAR2, p_default NUMBER) RETURN NUMBER IS
    v NUMBER;
  BEGIN
    SELECT TO_NUMBER(cfg_value) INTO v FROM SEC_CONFIG WHERE cfg_key = p_key;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN p_default;
    WHEN VALUE_ERROR   THEN RETURN p_default;
  END cfg_num;

  FUNCTION domain_of(p_domain_code IN VARCHAR2) RETURN t_domain IS
    v t_domain;
  BEGIN
    IF g_domains.EXISTS(p_domain_code) THEN
      RETURN g_domains(p_domain_code);
    END IF;
    SELECT norm_mode, mask_type, require_app_ctx, reveal_limit, audit_level
      INTO v.norm_mode, v.mask_type, v.require_app_ctx, v.reveal_limit, v.audit_level
      FROM SEC_DOMAIN
     WHERE domain_code = p_domain_code;
    g_domains(p_domain_code) := v;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_domain, p_domain_code);
      RETURN v;
  END domain_of;

  PROCEDURE slow_down IS
    v_cs NUMBER := cfg_num('FAIL_DELAY_CS', 0);
  BEGIN
    -- 실패에 지연을 두어 대량 시도를 억제한다. 기본은 0이며, 운영 상황을 보고
    -- 필요할 때만 올린다. 지연은 정상 사용자의 응답 시간에도 영향을 준다.
    IF v_cs > 0 THEN
      DBMS_LOCK.SLEEP(v_cs / 100);
    END IF;
  EXCEPTION
    WHEN OTHERS THEN NULL;
  END slow_down;

  FUNCTION mask_value(p_mask_type IN VARCHAR2, p_plain IN VARCHAR2) RETURN VARCHAR2 IS
    v_len PLS_INTEGER;
  BEGIN
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    v_len := LENGTH(p_plain);

    RETURN CASE p_mask_type
      -- 길이를 그대로 노출하지 않도록 고정 길이로 돌려준다.
      WHEN 'ALL'     THEN '********'
      -- 생년월일과 성별 자리까지만 남긴다.
      WHEN 'RRN'     THEN CASE WHEN v_len >= 8
                               THEN SUBSTR(p_plain, 1, 8) || '******'
                               ELSE '********' END
      WHEN 'NAME'    THEN CASE WHEN v_len <= 1 THEN '*'
                               WHEN v_len = 2  THEN SUBSTR(p_plain, 1, 1) || '*'
                               ELSE SUBSTR(p_plain, 1, 1)
                                    || RPAD('*', v_len - 2, '*')
                                    || SUBSTR(p_plain, -1) END
      WHEN 'ACCOUNT' THEN CASE WHEN v_len <= 4 THEN RPAD('*', v_len, '*')
                               ELSE RPAD('*', v_len - 4, '*') || SUBSTR(p_plain, -4) END
      WHEN 'EMAIL'   THEN CASE WHEN INSTR(p_plain, '@') > 2
                               THEN SUBSTR(p_plain, 1, 2) || '***'
                                    || SUBSTR(p_plain, INSTR(p_plain, '@'))
                               ELSE '***' || SUBSTR(p_plain, INSTR(p_plain, '@')) END
      WHEN 'PHONE'   THEN CASE WHEN v_len >= 7
                               THEN SUBSTR(p_plain, 1, 3) || RPAD('*', v_len - 7, '*')
                                    || SUBSTR(p_plain, -4)
                               ELSE RPAD('*', v_len, '*') END
      ELSE '********'
    END;
  END mask_value;

  FUNCTION can_reveal(p_domain_code IN VARCHAR2) RETURN VARCHAR2 IS
    v_dom t_domain := domain_of(p_domain_code);
  BEGIN
    IF v_dom.require_app_ctx = 'Y' AND NOT PKG_APP_CONTEXT.is_established THEN
      RETURN 'N';
    END IF;
    RETURN CASE WHEN PKG_AUTHZ.can_reveal(p_domain_code) THEN 'Y' ELSE 'N' END;
  END can_reveal;

  FUNCTION protect(p_domain_code IN VARCHAR2, p_plain IN VARCHAR2) RETURN RAW IS
  BEGIN
    -- 암호화는 정보를 내보내지 않으므로 복호화와 같은 수준의 통제를 두지 않는다.
    -- 다만 도메인이 정의되어 있어야 하며, 없는 도메인으로는 저장할 수 없다.
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN PKG_CRYPTO_CORE.encrypt_str(p_plain, p_domain_code);
  END protect;

  FUNCTION index_of(p_domain_code IN VARCHAR2, p_plain IN VARCHAR2) RETURN RAW IS
  BEGIN
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN PKG_CRYPTO_CORE.blind_index(p_plain, p_domain_code);
  END index_of;

  FUNCTION reveal(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
    v_dom   t_domain;
    v_plain VARCHAR2(32767);
    v_used  NUMBER;
  BEGIN
    IF p_cipher IS NULL THEN
      RETURN NULL;
    END IF;
    v_dom := domain_of(p_domain_code);

    -- 1. 정당한 애플리케이션 경로를 거쳤는가
    IF v_dom.require_app_ctx = 'Y' AND NOT PKG_APP_CONTEXT.is_established THEN
      PKG_AUDIT.bump_usage(p_domain_code, p_denied => 1);
      PKG_AUDIT.log('REVEAL_DENIED', 'ALERT', p_domain_code, '애플리케이션 문맥 없음');
      slow_down;
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_app_ctx);
    END IF;

    -- 2. 이 도메인을 평문으로 볼 자격이 있는가
    IF NOT PKG_AUTHZ.can_reveal(p_domain_code) THEN
      PKG_AUDIT.bump_usage(p_domain_code, p_denied => 1);
      PKG_AUDIT.log('REVEAL_DENIED', 'ALERT', p_domain_code, '복호화 권한 없음');
      slow_down;
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_reveal);
    END IF;

    -- 3. 정상 사용량을 넘지 않았는가
    IF v_dom.reveal_limit > 0 THEN
      v_used := PKG_AUDIT.usage_in_bucket(p_domain_code);
      IF v_used >= v_dom.reveal_limit THEN
        PKG_AUDIT.bump_usage(p_domain_code, p_denied => 1);
        PKG_AUDIT.log('RATE_EXCEEDED', 'ALERT', p_domain_code,
                      '구간 사용량 ' || v_used || ' / 임계치 ' || v_dom.reveal_limit,
                      v_used);
        PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_rate_limit);
      END IF;
    END IF;

    BEGIN
      v_plain := PKG_CRYPTO_CORE.decrypt_str(p_cipher);
    EXCEPTION
      WHEN OTHERS THEN
        -- 무결성 실패는 변조 또는 키 불일치를 뜻한다. 조용히 넘기지 않는다.
        PKG_AUDIT.log('INTEGRITY_FAIL', 'ALERT', p_domain_code,
                      'SQLCODE=' || SQLCODE);
        RAISE;
    END;

    PKG_AUDIT.bump_usage(p_domain_code, p_reveal => 1);
    IF v_dom.audit_level = 'FULL' THEN
      PKG_AUDIT.log('REVEAL', 'INFO', p_domain_code, NULL, 1);
    END IF;

    RETURN v_plain;
  END reveal;

  FUNCTION reveal_or_mask(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN
    IF p_cipher IS NULL THEN
      RETURN NULL;
    END IF;
    IF can_reveal(p_domain_code) = 'Y' THEN
      RETURN reveal(p_domain_code, p_cipher);
    END IF;
    RETURN mask(p_domain_code, p_cipher);
  END reveal_or_mask;

  FUNCTION mask(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
    v_dom t_domain;
  BEGIN
    IF p_cipher IS NULL THEN
      RETURN NULL;
    END IF;
    v_dom := domain_of(p_domain_code);
    -- 마스킹을 만들려면 일단 평문이 필요하다. 평문은 이 함수 밖으로 나가지 않는다.
    -- 다만 복호화 비용은 그대로 드므로, 대량 목록 화면에서는 마스킹된 값을 별도
    -- 컬럼으로 저장해 두는 편이 낫다.
    RETURN mask_value(v_dom.mask_type, PKG_CRYPTO_CORE.decrypt_str(p_cipher));
  EXCEPTION
    WHEN OTHERS THEN
      -- 한 건의 복호화 실패가 목록 전체를 막지 않게 한다. 대신 반드시 기록한다.
      PKG_AUDIT.log('MASK_FAIL', 'WARN', p_domain_code, 'SQLCODE=' || SQLCODE);
      RETURN '********';
  END mask;

END PKG_CRYPTO_POLICY;
/
