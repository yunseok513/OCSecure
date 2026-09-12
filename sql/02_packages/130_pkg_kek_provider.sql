-- 마스터 키 반입 계층
--
-- 마스터 키는 데이터베이스 안에 저장되지 않는다. 이 패키지가 유일한 반입 경로이며,
-- 반입된 키는 소유자 권한 패키지의 사설 변수에만 머문다. 호출자는 이 변수를 읽을
-- 수 없고, 이 패키지에 대한 실행 권한도 부여하지 않는다.
--
-- 반입 방식은 SEC_CONFIG 의 KEK_SOURCE 설정으로 고른다.
--
--   EXTERNAL    운영용. 외부 키 관리 서버나 하드웨어 보안 모듈에서 가져온다.
--               load_from_external 의 본문을 현장 환경에 맞게 구현해야 한다.
--               구현 전에는 오류를 낸다. 조용히 대체 경로로 넘어가지 않는다.
--
--   GLOBAL_CTX  개발과 시험 전용. 키 관리자가 인스턴스 기동 후 한 번 주입한다.
--               전역 문맥은 네임스페이스를 아는 세션이면 읽을 수 있으므로
--               운영계에서 사용해서는 안 된다.
--
-- 마스터 키를 잃으면 암호화된 데이터는 영구히 복구할 수 없다. 백업과 복구 시험을
-- 개통 전에 반드시 수행해야 한다.

CREATE OR REPLACE PACKAGE PKG_KEK_PROVIDER AS
  c_enc_label CONSTANT VARCHAR2(40) := 'OCSECURE/KEK/ENC/v1';
  c_mac_label CONSTANT VARCHAR2(40) := 'OCSECURE/KEK/MAC/v1';

  -- 개발/시험용 주입. KEK_SOURCE 가 GLOBAL_CTX 일 때만 동작한다.
  PROCEDURE set_master_key(p_kek IN RAW);
  PROCEDURE close_keystore;

  FUNCTION is_open   RETURN BOOLEAN;
  FUNCTION enc_subkey RETURN RAW;   -- 키 래핑용 암호화 키
  FUNCTION mac_subkey RETURN RAW;   -- 키 래핑용 무결성 키
END PKG_KEK_PROVIDER;
/

CREATE OR REPLACE PACKAGE BODY PKG_KEK_PROVIDER AS

  g_enc RAW(32);
  g_mac RAW(32);

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

  FUNCTION load_from_context RETURN RAW IS
    v_hex VARCHAR2(200) := SYS_CONTEXT('OCS_KEK_CTX', 'MASTER');
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

  PROCEDURE ensure_loaded IS
    v_src VARCHAR2(200);
  BEGIN
    IF g_enc IS NOT NULL THEN
      RETURN;
    END IF;
    v_src := cfg('KEK_SOURCE', 'EXTERNAL');
    IF v_src = 'GLOBAL_CTX' THEN
      derive(load_from_context);
    ELSIF v_src = 'EXTERNAL' THEN
      derive(load_from_external);
    ELSE
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config, 'KEK_SOURCE 설정값 오류: ' || v_src);
    END IF;
  END ensure_loaded;

  PROCEDURE set_master_key(p_kek IN RAW) IS
  BEGIN
    IF cfg('KEK_SOURCE', 'EXTERNAL') <> 'GLOBAL_CTX' THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config,
        'GLOBAL_CTX 모드가 아니면 마스터 키를 직접 주입할 수 없다');
    END IF;
    IF p_kek IS NULL OR UTL_RAW.LENGTH(p_kek) < 32 THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config, '마스터 키는 32바이트 이상이어야 한다');
    END IF;
    -- 전역 문맥이므로 모든 세션이 같은 값을 본다. 개발과 시험 전용이다.
    DBMS_SESSION.SET_CONTEXT('OCS_KEK_CTX', 'MASTER', RAWTOHEX(p_kek));
    derive(p_kek);
    PKG_AUDIT.log('KEYSTORE_OPEN', 'ALERT', NULL, '마스터 키 주입(GLOBAL_CTX 모드)');
  END set_master_key;

  PROCEDURE close_keystore IS
  BEGIN
    g_enc := NULL;
    g_mac := NULL;
    BEGIN
      DBMS_SESSION.CLEAR_CONTEXT('OCS_KEK_CTX', NULL, 'MASTER');
    EXCEPTION
      WHEN OTHERS THEN NULL;
    END;
    PKG_AUDIT.log('KEYSTORE_CLOSE', 'ALERT', NULL, '마스터 키 폐기');
  END close_keystore;

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
