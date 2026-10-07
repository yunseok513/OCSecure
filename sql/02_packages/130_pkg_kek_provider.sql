-- 마스터 키 반입 계층
--
-- 마스터 키는 데이터베이스 안에 저장되지 않는다. 이 패키지가 유일한 반입 경로이며,
-- EXTERNAL 방식에서는 반입된 키가 소유자 권한 패키지의 사설 변수에만 머문다. 호출자는
-- 이 변수를 읽을 수 없고, 이 패키지에 대한 실행 권한도 부여하지 않는다. GLOBAL_CTX
-- 방식에서는 키 값이 전역 문맥에 올라가므로 아래 설명을 보라.
--
-- 반입 방식은 SEC_CONFIG 의 KEK_SOURCE 설정으로 고른다.
--
--   EXTERNAL    운영용. 외부 키 관리 서버나 하드웨어 보안 모듈에서 가져온다.
--               load_from_external 의 본문을 현장 환경에 맞게 구현해야 한다.
--               구현 전에는 오류를 낸다. 조용히 대체 경로로 넘어가지 않는다.
--
--   SCOPED_CTX  외부 키 관리 서버나 하드웨어 보안 모듈을 도입할 수 없는 운영용.
--               전역 문맥에 올리되 값을 넣을 때 클라이언트 식별자를 설치마다 다른
--               무작위 토큰으로 지정한다. 토큰은 소유 계정만 읽는 SEC_CONFIG 에 있고
--               이 패키지만 읽을 때 잠깐 쓰므로, 응용 계정이 SYS_CONTEXT 로 직접
--               읽으면 빈 값이 나온다. 그러나 SYS 와 소유 계정을 쥔 사람, 키 유지
--               프로그램이 있는 장비의 관리자는 막지 못한다. 이 잔여 위험을 발주처가
--               문서로 수용했다고 SEC_CONFIG 의 KEK_RISK_ACK 에 남겨야 개통 판정을
--               통과한다(490_kek_risk_ack.sql).
--
--   GLOBAL_CTX  개발과 시험 전용. 키 관리자가 인스턴스 기동 후 한 번 주입한다.
--               전역 문맥은 네임스페이스를 아는 세션이면 읽을 수 있으므로
--               운영계에서 사용해서는 안 된다.
--
-- 마스터 키를 잃으면 암호화된 데이터는 영구히 복구할 수 없다. 백업과 복구 시험을
-- 개통 전에 반드시 수행해야 한다.
--
-- 닫기의 의미. 세션은 반입된 키에서 얻은 하위 키를 변수에 담아 쓴다. 한 세션이
-- close_keystore 로 전역 문맥을 비워도 다른 세션의 변수는 그대로이므로, 담아 둔 값을
-- 그냥 믿으면 이미 키를 올려 둔 세션(연결 풀의 응용 세션)은 저장소가 닫힌 뒤에도
-- 계속 쓴다. 그러면 사고 때 저장소를 닫아 암복호화를 멈춘다는 장치가 새 세션에만
-- 듣는다. 그래서 GLOBAL_CTX 로 올린 키는 쓸 때마다 전역 문맥에 같은 값이 아직 있는지
-- 확인하고, 없거나 바뀌었으면 담아 둔 값을 버린다. 비워졌으면 다음 호출이 오류로
-- 끝나고, 다른 값으로 바뀌었으면 새 값으로 다시 올린다.

CREATE OR REPLACE PACKAGE PKG_KEK_PROVIDER AS
  c_enc_label CONSTANT VARCHAR2(40) := 'OCSECURE/KEK/ENC/v1';
  c_mac_label CONSTANT VARCHAR2(40) := 'OCSECURE/KEK/MAC/v1';

  -- 개발/시험용 주입. KEK_SOURCE 가 GLOBAL_CTX 일 때만 동작한다.
  PROCEDURE set_master_key(p_kek IN RAW);
  PROCEDURE close_keystore;

  FUNCTION is_open   RETURN BOOLEAN;
  -- 마스터 키가 문맥에 올라 있으면 1. 값은 돌려주지 않는다. 키 유지 프로그램과
  -- 점검 스크립트가 쓴다(응용 계정은 이 패키지를 실행할 수 없다).
  FUNCTION context_present RETURN NUMBER;
  FUNCTION enc_subkey RETURN RAW;   -- 키 래핑용 암호화 키
  FUNCTION mac_subkey RETURN RAW;   -- 키 래핑용 무결성 키
END PKG_KEK_PROVIDER;
/

CREATE OR REPLACE PACKAGE BODY PKG_KEK_PROVIDER AS

  g_enc RAW(32);
  g_mac RAW(32);
  -- 이 하위 키를 어디서 얻었는지와, GLOBAL_CTX 라면 그때 전역 문맥에 있던 값. 쓸 때마다
  -- 전역 문맥과 맞춰 보기 위한 것이며 이 패키지의 사설 변수에만 머문다.
  g_src VARCHAR2(20);
  g_ctx VARCHAR2(200);
  -- SCOPED_CTX 의 토큰을 한 번 읽어 담아 둔다. 바뀌지 않는 값이며 이 패키지의 사설 변수에만 머문다.
  g_tok VARCHAR2(200);

  FUNCTION cfg(p_key VARCHAR2, p_default VARCHAR2) RETURN VARCHAR2 IS
    v VARCHAR2(200);
  BEGIN
    SELECT cfg_value INTO v FROM SEC_CONFIG WHERE cfg_key = p_key;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN p_default;
  END cfg;

  -- 현장 구현 지점. 외부 키 관리 서버 또는 하드웨어 보안 모듈에서 마스터 키를
  -- 가져오도록 이 본문을 교체한다. 지갑에 보관한 클라이언트 인증서로 상호 인증하는
  -- 방식을 권장한다. 가져온 값은 반환만 하고 어디에도 저장하지 않는다.
  FUNCTION load_from_external RETURN RAW IS
  BEGIN
    PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config,
      '외부 키 반입이 구현되지 않았다. PKG_KEK_PROVIDER.load_from_external 을 구현할 것');
    RETURN NULL;
  END load_from_external;

  c_ns CONSTANT VARCHAR2(30) := 'OCS_KEK_CTX';

  FUNCTION is_ctx_src(p_src VARCHAR2) RETURN BOOLEAN IS
  BEGIN
    RETURN p_src IN ('GLOBAL_CTX', 'SCOPED_CTX');
  END is_ctx_src;

  -- SCOPED_CTX 의 토큰. 없으면 p_create 일 때만 만든다. 응용 계정은 SEC_CONFIG 를 읽지
  -- 못하므로 이 값을 알 수 없다. 별도 트랜잭션으로 저장하여 호출한 쪽의 커밋과 무관하다.
  FUNCTION ctx_token(p_create IN BOOLEAN) RETURN VARCHAR2 IS
    PRAGMA AUTONOMOUS_TRANSACTION;
    v VARCHAR2(200);
  BEGIN
    IF g_tok IS NOT NULL THEN
      RETURN g_tok;
    END IF;
    BEGIN
      SELECT cfg_value INTO v FROM SEC_CONFIG WHERE cfg_key = 'KEK_CTX_TOKEN';
      g_tok := v;
      RETURN v;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN NULL;
    END;
    IF NOT p_create THEN
      RETURN NULL;
    END IF;
    v := RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(16));
    BEGIN
      INSERT INTO SEC_CONFIG (cfg_key, cfg_value, description)
      VALUES ('KEK_CTX_TOKEN', v,
              '마스터 키 문맥의 식별자 토큰(SCOPED_CTX). 값을 밖으로 내지 말고 바꾸지 말 것.');
      COMMIT;
    EXCEPTION
      WHEN DUP_VAL_ON_INDEX THEN
        ROLLBACK;
        SELECT cfg_value INTO v FROM SEC_CONFIG WHERE cfg_key = 'KEK_CTX_TOKEN';
    END;
    g_tok := v;
    RETURN v;
  END ctx_token;

  -- 전역 문맥의 마스터 키를 읽는다. SCOPED_CTX 는 클라이언트 식별자를 토큰으로 바꾸어
  -- 읽고, 읽은 직후 원래 값으로 되돌린다.
  FUNCTION read_ctx(p_src IN VARCHAR2) RETURN VARCHAR2 IS
    v_tok VARCHAR2(200);
    v_old VARCHAR2(256);
    v_val VARCHAR2(200);
  BEGIN
    IF p_src <> 'SCOPED_CTX' THEN
      RETURN SYS_CONTEXT(c_ns, 'MASTER');
    END IF;
    v_tok := ctx_token(FALSE);
    IF v_tok IS NULL THEN
      RETURN NULL;
    END IF;
    v_old := SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER');
    DBMS_SESSION.SET_IDENTIFIER(v_tok);
    BEGIN
      v_val := SYS_CONTEXT(c_ns, 'MASTER');
    EXCEPTION
      WHEN OTHERS THEN
        IF v_old IS NULL THEN DBMS_SESSION.CLEAR_IDENTIFIER;
        ELSE DBMS_SESSION.SET_IDENTIFIER(v_old); END IF;
        RAISE;
    END;
    IF v_old IS NULL THEN DBMS_SESSION.CLEAR_IDENTIFIER;
    ELSE DBMS_SESSION.SET_IDENTIFIER(v_old); END IF;
    RETURN v_val;
  END read_ctx;

  FUNCTION load_from_context(p_src IN VARCHAR2) RETURN RAW IS
    v_hex VARCHAR2(200) := read_ctx(p_src);
  BEGIN
    IF v_hex IS NULL THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_keystore_shut,
        '키 관리자가 마스터 키를 주입하지 않았다');
    END IF;
    RETURN HEXTORAW(v_hex);
  END load_from_context;

  PROCEDURE derive(p_kek IN RAW) IS
  BEGIN
    IF p_kek IS NULL OR UTL_RAW.LENGTH(p_kek) < 32 THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config, '마스터 키는 32바이트 이상이어야 한다');
    END IF;
    -- 라벨을 달리하여 용도가 다른 두 키를 얻는다. 마스터 키를 두 용도에 그대로
    -- 재사용하지 않기 위한 조치다.
    g_enc := PKG_PROVIDER_DBMS.mac(UTL_I18N.STRING_TO_RAW(c_enc_label, 'AL32UTF8'), p_kek);
    g_mac := PKG_PROVIDER_DBMS.mac(UTL_I18N.STRING_TO_RAW(c_mac_label, 'AL32UTF8'), p_kek);
  END derive;

  PROCEDURE drop_cached IS
  BEGIN
    g_enc := NULL;
    g_mac := NULL;
    g_src := NULL;
    g_ctx := NULL;
  END drop_cached;

  PROCEDURE ensure_loaded IS
    v_src VARCHAR2(200);
    v_raw RAW(100);
  BEGIN
    IF g_enc IS NOT NULL THEN
      -- 담아 둔 값을 믿기 전에 전역 문맥과 맞춰 본다. 문맥에 같은 값이 있으면 그대로 쓴다.
      IF is_ctx_src(g_src)
         AND UPPER(read_ctx(g_src)) = g_ctx THEN
        RETURN;
      END IF;
      IF NOT is_ctx_src(g_src) THEN
        RETURN;
      END IF;
      -- 비워졌거나 바뀌었다. 담아 둔 값을 버리고 아래에서 다시 올린다.
      drop_cached;
    END IF;
    v_src := cfg('KEK_SOURCE', 'EXTERNAL');
    IF is_ctx_src(v_src) THEN
      v_raw := load_from_context(v_src);   -- 문맥이 비어 있으면 여기서 오류로 끝난다
      derive(v_raw);
      g_src := v_src;
      g_ctx := RAWTOHEX(v_raw);
    ELSIF v_src = 'EXTERNAL' THEN
      derive(load_from_external);
      g_src := 'EXTERNAL';
    ELSE
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config, 'KEK_SOURCE 설정값 오류: ' || v_src);
    END IF;
  END ensure_loaded;

  PROCEDURE set_master_key(p_kek IN RAW) IS
    v_src VARCHAR2(20) := cfg('KEK_SOURCE', 'EXTERNAL');
  BEGIN
    IF NOT is_ctx_src(v_src) THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config,
        'GLOBAL_CTX 나 SCOPED_CTX 모드가 아니면 마스터 키를 직접 주입할 수 없다');
    END IF;
    IF p_kek IS NULL OR UTL_RAW.LENGTH(p_kek) < 32 THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config, '마스터 키는 32바이트 이상이어야 한다');
    END IF;
    IF v_src = 'SCOPED_CTX' THEN
      -- 토큰을 식별자로 지정하여 올린다. 토큰을 모르는 세션에는 보이지 않는다.
      DBMS_SESSION.SET_CONTEXT(c_ns, 'MASTER', RAWTOHEX(p_kek), NULL, ctx_token(TRUE));
    ELSE
      -- 전역 문맥이므로 모든 세션이 같은 값을 본다. 개발과 시험 전용이다.
      DBMS_SESSION.SET_CONTEXT(c_ns, 'MASTER', RAWTOHEX(p_kek));
    END IF;
    derive(p_kek);
    g_src := v_src;
    g_ctx := RAWTOHEX(p_kek);
    PKG_AUDIT.log('KEYSTORE_OPEN', 'ALERT', NULL, '마스터 키 주입(' || v_src || ' 모드)');
  END set_master_key;

  PROCEDURE close_keystore IS
    v_tok VARCHAR2(200);
  BEGIN
    drop_cached;
    -- 방식을 바꾸어 쓴 적이 있어도 남지 않도록 두 가지 모두 비운다.
    BEGIN
      DBMS_SESSION.CLEAR_CONTEXT(c_ns, NULL, 'MASTER');
    EXCEPTION
      WHEN OTHERS THEN NULL;
    END;
    BEGIN
      v_tok := ctx_token(FALSE);
      IF v_tok IS NOT NULL THEN
        DBMS_SESSION.CLEAR_CONTEXT(c_ns, v_tok, 'MASTER');
      END IF;
    EXCEPTION
      WHEN OTHERS THEN NULL;
    END;
    PKG_AUDIT.log('KEYSTORE_CLOSE', 'ALERT', NULL, '마스터 키 폐기');
  END close_keystore;

  FUNCTION context_present RETURN NUMBER IS
    v_src VARCHAR2(20) := cfg('KEK_SOURCE', 'EXTERNAL');
  BEGIN
    IF is_ctx_src(v_src) THEN
      RETURN CASE WHEN read_ctx(v_src) IS NOT NULL THEN 1 ELSE 0 END;
    END IF;
    RETURN CASE WHEN is_open THEN 1 ELSE 0 END;
  END context_present;

  FUNCTION is_open RETURN BOOLEAN IS
  BEGIN
    ensure_loaded;
    RETURN g_enc IS NOT NULL;
  EXCEPTION
    WHEN OTHERS THEN RETURN FALSE;
  END is_open;

  FUNCTION enc_subkey RETURN RAW IS
  BEGIN
    ensure_loaded;
    RETURN g_enc;
  END enc_subkey;

  FUNCTION mac_subkey RETURN RAW IS
  BEGIN
    ensure_loaded;
    RETURN g_mac;
  END mac_subkey;

END PKG_KEK_PROVIDER;
/
