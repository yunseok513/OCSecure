-- 암호 제공자 계층: 오라클 내장 기능 구현체
--
-- 이 계층은 교체 지점이다. 검증필 암호모듈이 확보되면 같은 규약을 따르는
-- PKG_PROVIDER_KCMVP 를 추가하고 PKG_CRYPTO_FMT 의 분기만 늘리면 되며,
-- 상위 계층과 애플리케이션은 손대지 않는다.
--
-- 이 계층이 하는 일은 블록 암복호화, 메시지 인증 코드, 해시, 난수 생성뿐이다.
-- 키 조회와 암호문 포맷 조립과 정책 판단은 이 계층의 책임이 아니다.
-- 이 경계가 무너지면 제공자 교체 시 상위 계층까지 함께 고쳐야 하므로,
-- 코드 검토에서 가장 먼저 확인할 항목이다.
--
-- 주의: 이 구현체는 개발과 시험용 임시 제공자다. 운영계 실데이터에는
--       검증필 제공자로 전환한 뒤에 적용해야 한다.

CREATE OR REPLACE PACKAGE PKG_PROVIDER_DBMS AS
  c_provider_name CONSTANT VARCHAR2(30) := 'DBMS_CRYPTO';

  -- 알고리즘 식별자. 0x10 이상 대역은 검증필 모듈용으로 남겨 둔다.
  c_alg_aes256_cbc CONSTANT PLS_INTEGER := 1;

  FUNCTION block_encrypt(p_plain IN RAW, p_key IN RAW, p_iv IN RAW, p_alg IN PLS_INTEGER)
    RETURN RAW;
  FUNCTION block_decrypt(p_cipher IN RAW, p_key IN RAW, p_iv IN RAW, p_alg IN PLS_INTEGER)
    RETURN RAW;
  FUNCTION mac(p_msg IN RAW, p_key IN RAW) RETURN RAW;      -- HMAC-SHA256
  FUNCTION digest(p_msg IN RAW) RETURN RAW;                 -- SHA-256
  FUNCTION random_bytes(p_len IN PLS_INTEGER) RETURN RAW;
  FUNCTION supports(p_alg IN PLS_INTEGER) RETURN BOOLEAN;
END PKG_PROVIDER_DBMS;
/

CREATE OR REPLACE PACKAGE BODY PKG_PROVIDER_DBMS AS

  c_aes256_cbc_pkcs5 CONSTANT PLS_INTEGER :=
    DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5;

  FUNCTION supports(p_alg IN PLS_INTEGER) RETURN BOOLEAN IS
  BEGIN
    RETURN p_alg = c_alg_aes256_cbc;
  END supports;

  PROCEDURE check_alg(p_alg IN PLS_INTEGER) IS
  BEGIN
    IF NOT supports(p_alg) THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg,
        '이 제공자가 지원하지 않는 알고리즘 식별자: ' || p_alg);
    END IF;
  END check_alg;

  FUNCTION block_encrypt(p_plain IN RAW, p_key IN RAW, p_iv IN RAW, p_alg IN PLS_INTEGER)
    RETURN RAW IS
  BEGIN
    check_alg(p_alg);
    RETURN DBMS_CRYPTO.ENCRYPT(src => p_plain, typ => c_aes256_cbc_pkcs5,
                               key => p_key,   iv  => p_iv);
  END block_encrypt;

  FUNCTION block_decrypt(p_cipher IN RAW, p_key IN RAW, p_iv IN RAW, p_alg IN PLS_INTEGER)
    RETURN RAW IS
  BEGIN
    check_alg(p_alg);
    RETURN DBMS_CRYPTO.DECRYPT(src => p_cipher, typ => c_aes256_cbc_pkcs5,
                               key => p_key,    iv  => p_iv);
  END block_decrypt;

  FUNCTION mac(p_msg IN RAW, p_key IN RAW) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.MAC(src => p_msg, typ => DBMS_CRYPTO.HMAC_SH256, key => p_key);
  END mac;

  FUNCTION digest(p_msg IN RAW) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.HASH(src => p_msg, typ => DBMS_CRYPTO.HASH_SH256);
  END digest;

  FUNCTION random_bytes(p_len IN PLS_INTEGER) RETURN RAW IS
  BEGIN
    -- 일반 난수 함수를 쓰지 않는다. 초기화 벡터와 솔트는 암호학적 난수여야 한다.
    RETURN DBMS_CRYPTO.RANDOMBYTES(p_len);
  END random_bytes;

END PKG_PROVIDER_DBMS;
/
