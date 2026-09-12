-- 키 저장소
--
-- 데이터 암호화 키는 마스터 키로 감싼 상태로만 테이블에 있다. 이 패키지가 그것을
-- 풀어 세션 안에서만 쓰고, 반복 조회를 피하기 위해 짧은 시간 캐시한다.
--
-- 키 상태의 의미는 다음과 같다. ACTIVE 는 신규 암호화에 쓰는 키이며 도메인마다
-- 하나뿐이다. RETIRING 은 복호화에만 쓰는 키로, 교체 중 기존 데이터를 읽기 위해
-- 남겨 둔다. RETIRED 는 더 이상 쓰지 않는 키이며 복호화도 거부한다.
-- 이 세 단계가 있어야 서비스를 멈추지 않고 키를 바꿀 수 있다.

CREATE OR REPLACE PACKAGE PKG_KEY_STORE AS

  TYPE t_keyset IS RECORD (
    key_id      PLS_INTEGER,
    domain_code VARCHAR2(30),
    alg_id      PLS_INTEGER,
    key_state   VARCHAR2(10),
    enc_key     RAW(32),
    mac_key     RAW(32),
    idx_key     RAW(32));

  FUNCTION get_active(p_domain_code IN VARCHAR2) RETURN t_keyset;
  FUNCTION get_by_id (p_key_id      IN PLS_INTEGER) RETURN t_keyset;

  FUNCTION wrap  (p_raw_key IN RAW) RETURN RAW;
  FUNCTION unwrap(p_wrapped IN RAW) RETURN RAW;

  PROCEDURE flush_cache;

  -- 캐시 유효 시간(초). 키 상태 변경이 이 시간 안에 모든 세션에 전파된다.
  c_cache_ttl_sec CONSTANT PLS_INTEGER := 60;
END PKG_KEY_STORE;
/

CREATE OR REPLACE PACKAGE BODY PKG_KEY_STORE AS

  TYPE t_key_cache    IS TABLE OF t_keyset    INDEX BY PLS_INTEGER;
  TYPE t_active_cache IS TABLE OF PLS_INTEGER INDEX BY VARCHAR2(30);

  g_keys        t_key_cache;
  g_active      t_active_cache;
  g_active_at   PLS_INTEGER := 0;   -- DBMS_UTILITY.GET_TIME 기준 1/100초

  FUNCTION wrap(p_raw_key IN RAW) RETURN RAW IS
  BEGIN
    -- 키 자료도 데이터와 같은 포맷으로 감싼다. 키 식별자 자리에는 0을 쓴다.
    RETURN PKG_CRYPTO_FMT.pack(
             p_plain   => p_raw_key,
             p_key_id  => 0,
             p_alg_id  => PKG_PROVIDER_DBMS.c_alg_aes256_cbc,
             p_enc_key => PKG_KEK_PROVIDER.enc_subkey,
             p_mac_key => PKG_KEK_PROVIDER.mac_subkey);
  END wrap;

  FUNCTION unwrap(p_wrapped IN RAW) RETURN RAW IS
  BEGIN
    RETURN PKG_CRYPTO_FMT.unpack(p_wrapped,
                                 PKG_KEK_PROVIDER.enc_subkey,
                                 PKG_KEK_PROVIDER.mac_subkey);
  END unwrap;

  PROCEDURE flush_cache IS
  BEGIN
    g_keys.DELETE;
    g_active.DELETE;
    g_active_at := 0;
  END flush_cache;

  FUNCTION load(p_key_id IN PLS_INTEGER) RETURN t_keyset IS
    v t_keyset;
    v_enc_w RAW(256);
    v_mac_w RAW(256);
    v_idx_w RAW(256);
  BEGIN
    SELECT key_id, domain_code, alg_id, key_state,
           enc_key_wrapped, mac_key_wrapped, idx_key_wrapped
      INTO v.key_id, v.domain_code, v.alg_id, v.key_state,
           v_enc_w, v_mac_w, v_idx_w
      FROM SEC_KEY
     WHERE key_id = p_key_id;

    IF v.key_state = 'RETIRED' THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_key_missing, '폐기된 키: ' || p_key_id);
    END IF;

    v.enc_key := unwrap(v_enc_w);
    v.mac_key := unwrap(v_mac_w);
    v.idx_key := unwrap(v_idx_w);
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_key_missing, '키 식별자 없음: ' || p_key_id);
      RETURN v;
  END load;

  FUNCTION get_by_id(p_key_id IN PLS_INTEGER) RETURN t_keyset IS
  BEGIN
    IF p_key_id IS NULL THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '키 식별자가 비어 있음');
    END IF;
    IF NOT g_keys.EXISTS(p_key_id) THEN
      g_keys(p_key_id) := load(p_key_id);
    END IF;
    RETURN g_keys(p_key_id);
  END get_by_id;

  FUNCTION get_active(p_domain_code IN VARCHAR2) RETURN t_keyset IS
    v_key_id PLS_INTEGER;
    v_now    PLS_INTEGER := DBMS_UTILITY.GET_TIME;
  BEGIN
    -- 활성 키는 교체될 수 있으므로 짧은 유효 시간을 두고 다시 읽는다.
    IF v_now - g_active_at > c_cache_ttl_sec * 100 OR v_now < g_active_at THEN
      g_active.DELETE;
      g_active_at := v_now;
    END IF;

    IF g_active.EXISTS(p_domain_code) THEN
      v_key_id := g_active(p_domain_code);
    ELSE
      BEGIN
        SELECT key_id INTO v_key_id
          FROM SEC_KEY
         WHERE domain_code = p_domain_code
           AND key_state   = 'ACTIVE';
      EXCEPTION
        WHEN NO_DATA_FOUND THEN
          PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_key_missing,
            '활성 키 없음: 도메인 ' || p_domain_code);
      END;
      g_active(p_domain_code) := v_key_id;
    END IF;

    RETURN get_by_id(v_key_id);
  END get_active;

END PKG_KEY_STORE;
/
