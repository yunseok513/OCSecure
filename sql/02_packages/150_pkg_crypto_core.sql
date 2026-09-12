-- 암호 연산 계층
--
-- 키를 조회하고 문자열을 바이트열로 바꾸고 포맷을 조립하는 일까지를 맡는다.
-- 정책 판단과 권한 확인은 하지 않는다. 그것은 상위 정책 계층의 책임이다.
--
-- 이 패키지에는 어떤 계정에도 실행 권한을 부여하지 않는다. 부여하는 순간 정책
-- 계층을 우회하여 무제한 복호화가 가능해지므로, 권한 점검의 핵심 항목이다.
--
-- 문자열은 데이터베이스 문자집합과 무관하게 항상 UTF-8 로 인코딩한다.
--
-- 오라클에서 빈 문자열은 NULL 이므로, 빈 문자열을 넣으면 NULL 이 나온다.
-- 참조 구현(파이썬)과 다른 유일한 지점이며 의도된 동작이다.

CREATE OR REPLACE PACKAGE PKG_CRYPTO_CORE AS

  c_charset CONSTANT VARCHAR2(30) := 'AL32UTF8';

  c_kdf_version CONSTANT PLS_INTEGER := 1;
  c_kdf_pbkdf2  CONSTANT PLS_INTEGER := 1;
  c_pwd_salt_len CONSTANT PLS_INTEGER := 16;
  c_pwd_dk_len   CONSTANT PLS_INTEGER := 32;
  c_pwd_blob_len CONSTANT PLS_INTEGER := 2 + 4 + 16 + 32;   -- 54

  -- 양방향 --------------------------------------------------------------
  -- p_iv 는 고정 시험 벡터 대조 전용이다. 업무 호출에서는 반드시 비워 두어
  -- 매번 새 난수를 쓰게 한다. 같은 평문이 같은 암호문이 되면 빈도 분석에 노출된다.
  FUNCTION encrypt_str(p_plain       IN VARCHAR2,
                       p_domain_code IN VARCHAR2,
                       p_iv          IN RAW DEFAULT NULL) RETURN RAW;

  FUNCTION decrypt_str(p_cipher IN RAW) RETURN VARCHAR2;

  -- 검색용 색인 -----------------------------------------------------------
  FUNCTION blind_index(p_plain       IN VARCHAR2,
                       p_domain_code IN VARCHAR2) RETURN RAW;

  FUNCTION normalize(p_plain IN VARCHAR2, p_mode IN VARCHAR2) RETURN VARCHAR2;

  -- 일방향 ----------------------------------------------------------------
  FUNCTION pwd_hash(p_password   IN VARCHAR2,
                    p_salt       IN RAW         DEFAULT NULL,
                    p_iterations IN PLS_INTEGER DEFAULT NULL) RETURN RAW;

  FUNCTION pwd_verify(p_password IN VARCHAR2, p_stored IN RAW) RETURN BOOLEAN;

  -- 저장된 해시의 반복 횟수가 현재 기준보다 낮으면 참을 돌려준다.
  -- 로그인 성공 시점에 다시 계산하여 점진적으로 상향하기 위한 판정이다.
  FUNCTION pwd_needs_upgrade(p_stored IN RAW) RETURN BOOLEAN;

  FUNCTION pbkdf2_sha256(p_password   IN RAW,
                         p_salt       IN RAW,
                         p_iterations IN PLS_INTEGER) RETURN RAW;
END PKG_CRYPTO_CORE;
/

CREATE OR REPLACE PACKAGE BODY PKG_CRYPTO_CORE AS

  FUNCTION cfg_num(p_key VARCHAR2, p_default NUMBER) RETURN NUMBER IS
    v NUMBER;
  BEGIN
    SELECT TO_NUMBER(cfg_value) INTO v FROM SEC_CONFIG WHERE cfg_key = p_key;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN p_default;
    WHEN VALUE_ERROR   THEN RETURN p_default;
  END cfg_num;

  FUNCTION to_utf8(p_s IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN UTL_I18N.STRING_TO_RAW(p_s, c_charset);
  END to_utf8;

  FUNCTION from_utf8(p_r IN RAW) RETURN VARCHAR2 IS
  BEGIN
    RETURN UTL_I18N.RAW_TO_CHAR(p_r, c_charset);
  END from_utf8;

  FUNCTION normalize(p_plain IN VARCHAR2, p_mode IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN CASE p_mode
             WHEN 'NONE'       THEN p_plain
             WHEN 'TRIM'       THEN TRIM(' ' FROM p_plain)
             WHEN 'UPPER_TRIM' THEN UPPER(TRIM(' ' FROM p_plain))
             WHEN 'DIGITS'     THEN REGEXP_REPLACE(p_plain, '[^0-9]', '')
           END;
  END normalize;

  FUNCTION domain_norm(p_domain_code IN VARCHAR2) RETURN VARCHAR2 IS
    v VARCHAR2(12);
  BEGIN
    SELECT norm_mode INTO v FROM SEC_DOMAIN WHERE domain_code = p_domain_code;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_domain, p_domain_code);
      RETURN NULL;
  END domain_norm;

  FUNCTION encrypt_str(p_plain       IN VARCHAR2,
                       p_domain_code IN VARCHAR2,
                       p_iv          IN RAW DEFAULT NULL) RETURN RAW IS
    v_key PKG_KEY_STORE.t_keyset;
  BEGIN
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    v_key := PKG_KEY_STORE.get_active(p_domain_code);
    RETURN PKG_CRYPTO_FMT.pack(p_plain   => to_utf8(p_plain),
                               p_key_id  => v_key.key_id,
                               p_alg_id  => v_key.alg_id,
                               p_enc_key => v_key.enc_key,
                               p_mac_key => v_key.mac_key,
                               p_iv      => p_iv);
  END encrypt_str;

  FUNCTION decrypt_str(p_cipher IN RAW) RETURN VARCHAR2 IS
    v_key PKG_KEY_STORE.t_keyset;
  BEGIN
    IF p_cipher IS NULL THEN
      RETURN NULL;
    END IF;
    -- 헤더의 키 식별자로 어느 키로 만들어진 암호문인지 판별한다. 키를 교체해도
    -- 기존 데이터를 읽을 수 있는 것은 이 한 줄 덕분이다.
    v_key := PKG_KEY_STORE.get_by_id(PKG_CRYPTO_FMT.key_id_of(p_cipher));
    RETURN from_utf8(PKG_CRYPTO_FMT.unpack(p_cipher, v_key.enc_key, v_key.mac_key));
  END decrypt_str;

  FUNCTION blind_index(p_plain       IN VARCHAR2,
                       p_domain_code IN VARCHAR2) RETURN RAW IS
    v_key  PKG_KEY_STORE.t_keyset;
    v_norm VARCHAR2(4000);
  BEGIN
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    -- 단순 해시를 쓰지 않는다. 주민등록번호처럼 값의 범위가 좁은 데이터는
    -- 전수 대입으로 원문이 복원되므로, 키가 결합된 HMAC 이어야 한다.
    v_key  := PKG_KEY_STORE.get_active(p_domain_code);
    v_norm := normalize(p_plain, domain_norm(p_domain_code));
    IF v_norm IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN PKG_PROVIDER_DBMS.mac(to_utf8(v_norm), v_key.idx_key);
  END blind_index;

  FUNCTION pbkdf2_sha256(p_password   IN RAW,
                         p_salt       IN RAW,
                         p_iterations IN PLS_INTEGER) RETURN RAW IS
    v_u RAW(32);
    v_t RAW(32);
  BEGIN
    -- 출력 길이가 해시 출력과 같으므로 블록은 하나뿐이다. 참조 구현과 동일한 구조다.
    v_u := PKG_PROVIDER_DBMS.mac(UTL_RAW.CONCAT(p_salt, HEXTORAW('00000001')), p_password);
    v_t := v_u;
    FOR i IN 2 .. p_iterations LOOP
      v_u := PKG_PROVIDER_DBMS.mac(v_u, p_password);
      v_t := UTL_RAW.BIT_XOR(v_t, v_u);
    END LOOP;
    RETURN v_t;
  END pbkdf2_sha256;

  FUNCTION pwd_hash(p_password   IN VARCHAR2,
                    p_salt       IN RAW         DEFAULT NULL,
                    p_iterations IN PLS_INTEGER DEFAULT NULL) RETURN RAW IS
    v_salt RAW(16);
    v_iter PLS_INTEGER;
  BEGIN
    IF p_password IS NULL THEN
      RETURN NULL;
    END IF;
    v_salt := NVL(p_salt, PKG_PROVIDER_DBMS.random_bytes(c_pwd_salt_len));
    v_iter := NVL(p_iterations, cfg_num('PWD_ITERATIONS', 10000));
    IF v_iter < 1 THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_config, '반복 횟수가 1보다 작음');
    END IF;
    IF UTL_RAW.LENGTH(v_salt) <> c_pwd_salt_len THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '솔트 길이 오류');
    END IF;

    -- 반복 횟수를 블롭에 담으므로, 나중에 횟수를 올려도 기존 사용자와 공존한다.
    RETURN UTL_RAW.CONCAT(
             PKG_CRYPTO_FMT.byte_of(c_kdf_version),
             PKG_CRYPTO_FMT.byte_of(c_kdf_pbkdf2),
             PKG_CRYPTO_FMT.dword_of(v_iter),
             v_salt,
             pbkdf2_sha256(to_utf8(p_password), v_salt, v_iter));
  END pwd_hash;

  FUNCTION pwd_verify(p_password IN VARCHAR2, p_stored IN RAW) RETURN BOOLEAN IS
    v_iter PLS_INTEGER;
    v_salt RAW(16);
    v_dk   RAW(32);
  BEGIN
    IF p_password IS NULL OR p_stored IS NULL
       OR UTL_RAW.LENGTH(p_stored) <> c_pwd_blob_len THEN
      RETURN FALSE;
    END IF;
    IF PKG_CRYPTO_FMT.int_of(UTL_RAW.SUBSTR(p_stored, 1, 1)) <> c_kdf_version
       OR PKG_CRYPTO_FMT.int_of(UTL_RAW.SUBSTR(p_stored, 2, 1)) <> c_kdf_pbkdf2 THEN
      RETURN FALSE;
    END IF;

    v_iter := PKG_CRYPTO_FMT.int_of(UTL_RAW.SUBSTR(p_stored, 3, 4));
    v_salt := UTL_RAW.SUBSTR(p_stored, 7, c_pwd_salt_len);
    v_dk   := UTL_RAW.SUBSTR(p_stored, 7 + c_pwd_salt_len, c_pwd_dk_len);

    RETURN PKG_CRYPTO_FMT.const_eq(pbkdf2_sha256(to_utf8(p_password), v_salt, v_iter), v_dk);
  END pwd_verify;

  FUNCTION pwd_needs_upgrade(p_stored IN RAW) RETURN BOOLEAN IS
  BEGIN
    IF p_stored IS NULL OR UTL_RAW.LENGTH(p_stored) <> c_pwd_blob_len THEN
      RETURN TRUE;
    END IF;
    RETURN PKG_CRYPTO_FMT.int_of(UTL_RAW.SUBSTR(p_stored, 3, 4))
             < cfg_num('PWD_ITERATIONS', 10000);
  END pwd_needs_upgrade;

END PKG_CRYPTO_CORE;
/
