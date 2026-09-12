-- 암호문 포맷 계층
--
-- 블롭 = ver(1) | alg(1) | key_id(2) | iv(16) | ciphertext(n) | tag(32)
--
-- 태그는 ver 부터 ciphertext 까지 전체에 대한 HMAC-SHA256 이다. 곧 Encrypt-then-MAC
-- 이며, 복호화 시 태그를 먼저 검증하고 실패하면 복호화 자체를 수행하지 않는다.
-- 이 순서를 바꾸면 암호문 조작 공격의 여지가 생긴다.
--
-- 헤더에 버전과 알고리즘과 키 식별자를 담는 이유는 교체 때문이다. 이것이 없으면
-- 키를 바꾸는 순간 기존 데이터를 복호화할 수 없게 되어 키 교체가 불가능해진다.
--
-- 이 패키지의 계산 결과는 tools/refimpl/ocsecure_ref.py 와 바이트 단위로 같아야
-- 한다. sql/09_test 의 고정 시험 벡터가 그것을 확인한다.

CREATE OR REPLACE PACKAGE PKG_CRYPTO_FMT AS
  c_fmt_version CONSTANT PLS_INTEGER := 1;
  c_iv_len      CONSTANT PLS_INTEGER := 16;
  c_tag_len     CONSTANT PLS_INTEGER := 32;
  c_hdr_len     CONSTANT PLS_INTEGER := 4;
  c_min_len     CONSTANT PLS_INTEGER := 4 + 16 + 16 + 32;   -- 68

  -- 평문 바이트열을 감싼다. p_iv 는 고정 시험 벡터 대조용이며 통상은 NULL 로 두어
  -- 매번 새 난수를 쓰게 한다(확률적 암호화).
  FUNCTION pack(p_plain   IN RAW,
                p_key_id  IN PLS_INTEGER,
                p_alg_id  IN PLS_INTEGER,
                p_enc_key IN RAW,
                p_mac_key IN RAW,
                p_iv      IN RAW DEFAULT NULL) RETURN RAW;

  FUNCTION unpack(p_blob    IN RAW,
                  p_enc_key IN RAW,
                  p_mac_key IN RAW) RETURN RAW;

  FUNCTION version_of(p_blob IN RAW) RETURN PLS_INTEGER;
  FUNCTION alg_id_of (p_blob IN RAW) RETURN PLS_INTEGER;
  FUNCTION key_id_of (p_blob IN RAW) RETURN PLS_INTEGER;

  -- 길이가 같으면 내용 차이와 무관하게 같은 시간이 걸리는 비교.
  FUNCTION const_eq(p_a IN RAW, p_b IN RAW) RETURN BOOLEAN;

  -- 바이트 조립 헬퍼. 바이트 배치는 이 패키지가 한 곳에서 책임진다.
  FUNCTION byte_of (p_n IN PLS_INTEGER) RETURN RAW;   -- 1바이트
  FUNCTION word_of (p_n IN PLS_INTEGER) RETURN RAW;   -- 2바이트 빅엔디언
  FUNCTION dword_of(p_n IN PLS_INTEGER) RETURN RAW;   -- 4바이트 빅엔디언
  FUNCTION int_of  (p_r IN RAW)         RETURN PLS_INTEGER;
END PKG_CRYPTO_FMT;
/

CREATE OR REPLACE PACKAGE BODY PKG_CRYPTO_FMT AS

  FUNCTION byte_of(p_n IN PLS_INTEGER) RETURN RAW IS
  BEGIN
    RETURN UTL_RAW.SUBSTR(UTL_RAW.CAST_FROM_BINARY_INTEGER(p_n), 4, 1);
  END byte_of;

  FUNCTION word_of(p_n IN PLS_INTEGER) RETURN RAW IS
  BEGIN
    RETURN UTL_RAW.SUBSTR(UTL_RAW.CAST_FROM_BINARY_INTEGER(p_n), 3, 2);
  END word_of;

  FUNCTION dword_of(p_n IN PLS_INTEGER) RETURN RAW IS
  BEGIN
    RETURN UTL_RAW.CAST_FROM_BINARY_INTEGER(p_n);
  END dword_of;

  FUNCTION int_of(p_r IN RAW) RETURN PLS_INTEGER IS
  BEGIN
    RETURN UTL_RAW.CAST_TO_BINARY_INTEGER(
             UTL_RAW.CONCAT(UTL_RAW.COPIES(HEXTORAW('00'), 4 - UTL_RAW.LENGTH(p_r)), p_r));
  END int_of;

  FUNCTION const_eq(p_a IN RAW, p_b IN RAW) RETURN BOOLEAN IS
  BEGIN
    IF p_a IS NULL OR p_b IS NULL THEN
      RETURN FALSE;
    END IF;
    IF UTL_RAW.LENGTH(p_a) <> UTL_RAW.LENGTH(p_b) THEN
      RETURN FALSE;
    END IF;
    RETURN UTL_RAW.BIT_XOR(p_a, p_b)
             = UTL_RAW.COPIES(HEXTORAW('00'), UTL_RAW.LENGTH(p_a));
  END const_eq;

  PROCEDURE check_blob(p_blob IN RAW) IS
  BEGIN
    IF p_blob IS NULL THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_format, '암호문이 비어 있음');
    END IF;
    IF UTL_RAW.LENGTH(p_blob) < c_min_len THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_format,
        '길이 부족: ' || UTL_RAW.LENGTH(p_blob) || ' < ' || c_min_len);
    END IF;
    IF int_of(UTL_RAW.SUBSTR(p_blob, 1, 1)) <> c_fmt_version THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_format,
        '알 수 없는 포맷 버전: ' || int_of(UTL_RAW.SUBSTR(p_blob, 1, 1)));
    END IF;
  END check_blob;

  FUNCTION version_of(p_blob IN RAW) RETURN PLS_INTEGER IS
  BEGIN
    check_blob(p_blob);
    RETURN int_of(UTL_RAW.SUBSTR(p_blob, 1, 1));
  END version_of;

  FUNCTION alg_id_of(p_blob IN RAW) RETURN PLS_INTEGER IS
  BEGIN
    check_blob(p_blob);
    RETURN int_of(UTL_RAW.SUBSTR(p_blob, 2, 1));
  END alg_id_of;

  FUNCTION key_id_of(p_blob IN RAW) RETURN PLS_INTEGER IS
  BEGIN
    check_blob(p_blob);
    RETURN int_of(UTL_RAW.SUBSTR(p_blob, 3, 2));
  END key_id_of;

  FUNCTION pack(p_plain   IN RAW,
                p_key_id  IN PLS_INTEGER,
                p_alg_id  IN PLS_INTEGER,
                p_enc_key IN RAW,
                p_mac_key IN RAW,
                p_iv      IN RAW DEFAULT NULL) RETURN RAW IS
    v_iv     RAW(16);
    v_ct     RAW(32767);
    v_signed RAW(32767);
  BEGIN
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    IF p_key_id IS NULL OR p_key_id < 0 OR p_key_id > 65535 THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '키 식별자 범위 초과');
    END IF;
    IF UTL_RAW.LENGTH(p_enc_key) <> 32 OR UTL_RAW.LENGTH(p_mac_key) <> 32 THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '키 길이는 32바이트여야 함');
    END IF;

    v_iv := NVL(p_iv, PKG_PROVIDER_DBMS.random_bytes(c_iv_len));
    IF UTL_RAW.LENGTH(v_iv) <> c_iv_len THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '초기화 벡터 길이 오류');
    END IF;

    v_ct := PKG_PROVIDER_DBMS.block_encrypt(p_plain, p_enc_key, v_iv, p_alg_id);

    v_signed := UTL_RAW.CONCAT(byte_of(c_fmt_version), byte_of(p_alg_id),
                               word_of(p_key_id), v_iv, v_ct);

    RETURN UTL_RAW.CONCAT(v_signed, PKG_PROVIDER_DBMS.mac(v_signed, p_mac_key));
  END pack;

  FUNCTION unpack(p_blob    IN RAW,
                  p_enc_key IN RAW,
                  p_mac_key IN RAW) RETURN RAW IS
    v_len    PLS_INTEGER;
    v_signed RAW(32767);
    v_tag    RAW(32);
    v_iv     RAW(16);
    v_ct     RAW(32767);
  BEGIN
    IF p_blob IS NULL THEN
      RETURN NULL;
    END IF;
    check_blob(p_blob);

    v_len    := UTL_RAW.LENGTH(p_blob);
    v_signed := UTL_RAW.SUBSTR(p_blob, 1, v_len - c_tag_len);
    v_tag    := UTL_RAW.SUBSTR(p_blob, v_len - c_tag_len + 1, c_tag_len);

    -- 무결성 검증이 먼저다. 실패하면 복호화를 시도조차 하지 않는다.
    IF NOT const_eq(PKG_PROVIDER_DBMS.mac(v_signed, p_mac_key), v_tag) THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_integrity);
    END IF;

    v_iv := UTL_RAW.SUBSTR(p_blob, c_hdr_len + 1, c_iv_len);
    v_ct := UTL_RAW.SUBSTR(p_blob, c_hdr_len + c_iv_len + 1,
                           v_len - c_tag_len - c_hdr_len - c_iv_len);

    RETURN PKG_PROVIDER_DBMS.block_decrypt(v_ct, p_enc_key, v_iv,
                                           int_of(UTL_RAW.SUBSTR(p_blob, 2, 1)));
  END unpack;

END PKG_CRYPTO_FMT;
/
