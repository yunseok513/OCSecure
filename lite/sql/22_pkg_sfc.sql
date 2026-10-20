@@05_check_charset.sql
-- OCS-LITE 4단계 (SFC_OWNER 로 접속)
--
-- PKG_SFC: 모듈 전체를 담은 패키지입니다.
--
-- 암호문 형식은 전체판과 같아서 자료를 서로 옮길 수 있습니다.
--   버전(1) | 알고리즘(1) | 키 번호(2) | IV(16) | AES-256-CBC 암호문 | HMAC-SHA256 태그(32)
-- 태그는 앞의 모든 바이트에 대한 값이며 복호화 전에 먼저 검증합니다.
-- 문자열은 데이터베이스 문자집합과 관계없이 항상 UTF-8 로 다룹니다.
-- 저장 형태는 암호문을 대문자 16진수로 쓴 문자열입니다. 13글자 값은 136자가 됩니다.
--
-- 이 패키지는 소유 계정 외에는 누구에게도 권한을 주지 않습니다. 응용은 23_functions.sql 의
-- FN_SFC_* 함수만 호출합니다.
--
-- 오류는 모두 예외로 던집니다 (오류 번호는 아래 명세 참조).

CREATE OR REPLACE PACKAGE PKG_SFC AS

  -- 이 패키지가 일으키는 오류 번호입니다 (안내서 제7장 참조).
  --   e_bad_arg     호출이 잘못됨: 빈 비밀번호, 너무 긴 평문, 알 수 없는 마스킹 유형
  --   e_no_key      활성 키가 없음, 키 번호를 찾을 수 없음, 키 테이블과 봉인값이 맞지 않음
  --   e_integrity   암호문이 변조되었거나 다른 키로 만든 값임
  --   e_bad_format  이 모듈의 암호문이 아님: 16진수가 아니거나, 너무 짧거나, 버전이 다름
  --   e_state       init_key 를 두 번 실행했거나, init_key 전에 rotate_key 를 실행함
  e_bad_arg    CONSTANT PLS_INTEGER := -20601;
  e_no_key     CONSTANT PLS_INTEGER := -20602;
  e_integrity  CONSTANT PLS_INTEGER := -20603;
  e_bad_format CONSTANT PLS_INTEGER := -20604;
  e_state      CONSTANT PLS_INTEGER := -20605;

  -- 새로 만드는 비밀번호 해시에 쓰는 PBKDF2 반복 횟수입니다.
  -- 이미 저장된 해시는 만들 때의 횟수를 그대로 가지며 계속 유효합니다.
  -- 바꾸려면 이 값을 고치고, 이 패키지를 다시 컴파일하고, 안내서 4.2절의 숫자를 고칩니다.
  c_pwd_iterations CONSTANT PLS_INTEGER := 10000;

  -- ===== 식별번호 (양방향) =================================================
  -- 응용은 이 패키지가 아니라 FN_SFC_* 함수를 호출합니다.

  -- encrypt_hex: 주민등록번호, 계좌번호 같은 짧은 문자열을 암호화합니다.
  --   p_plain  평문. NULL 이면 NULL 을 돌려줍니다. UTF-8 로 1900바이트 이하 (한글은 글자당 3바이트).
  --   p_iv     시험 전용입니다. NULL 로 두면 호출마다 새 난수를 씁니다.
  -- 반환       대문자 16진 문자열. 13글자 값이면 136자이므로 저장할 컬럼 길이를 맞춰 두십시오
  --            (안내서 제2장). 같은 평문도 호출마다 결과가 달라 WHERE 조건에는 쓸 수 없습니다.
  -- 오류       -20601 평문이 너무 김, -20602 사용할 수 있는 키가 없음.
  FUNCTION encrypt_hex(p_plain IN VARCHAR2, p_iv IN RAW DEFAULT NULL) RETURN VARCHAR2;

  -- decrypt_hex: encrypt_hex 로 만든 값에서 원래 문자열을 되돌립니다.
  --   p_hex    저장된 값. NULL 이면 NULL 을 돌려줍니다.
  -- 반환       원래 문자열.
  -- 오류       -20604 이 모듈의 값이 아님 (예: 컬럼이 짧아 값이 잘림), -20603 변조된 값,
  --            -20602 키를 찾을 수 없음.
  FUNCTION decrypt_hex(p_hex   IN VARCHAR2) RETURN VARCHAR2;

  -- mask_hex: 저장된 값을 복호화해 일부를 가려서 돌려줍니다.
  --   p_hex    저장된 값. NULL 이면 NULL 을 돌려줍니다.
  --   p_type   RRN      숫자 13자리: 앞 6자리, 하이픈, 별표 7개 (900101-*******)
  --                     자리수가 다르면 전부 가림
  --            ACCOUNT  앞 4글자만 보이고 나머지는 별표. 4글자 이하이면 전부 가림
  --            ALL      항상 ******** (기본값)
  -- 반환       가려진 문자열.
  -- 오류       -20601 알 수 없는 p_type, 그리고 decrypt_hex 의 오류.
  FUNCTION mask_hex(p_hex IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2;

  -- mask_value: mask_hex 와 같은 가림 규칙을, 이미 가지고 있는 평문에 적용합니다.
  --   p_plain  평문. NULL 이면 NULL 을 돌려줍니다.
  --   p_type   RRN | ACCOUNT | ALL (mask_hex 와 같음).
  -- 오류       -20601 알 수 없는 p_type.
  FUNCTION mask_value(p_plain IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2;

  -- ===== 비밀번호 (일방향) =================================================

  -- pwd_hash_hex: 비밀번호로 저장할 값을 만듭니다. 이 값에서 비밀번호를 되돌릴 수 없습니다.
  --   p_password  비밀번호. NULL 이나 빈 문자열은 거부합니다.
  --   p_salt      시험 전용입니다. NULL 로 두면 호출마다 새 난수를 씁니다.
  --   p_iter      반복 횟수. NULL 이면 c_pwd_iterations 를 씁니다. 소유 계정은 이 값을 지정해
  --               아무것도 바꾸지 않고 후보 횟수의 소요 시간을 잴 수 있습니다.
  -- 반환          108자 16진 문자열. 같은 비밀번호도 호출마다 결과가 다른 것이 정상입니다.
  --               비밀번호 확인은 pwd_verify_hex 로 합니다.
  -- 오류          -20601 빈 비밀번호, 반복 횟수가 1 미만, 솔트가 16바이트가 아님.
  FUNCTION pwd_hash_hex(p_password IN VARCHAR2,
                        p_salt     IN RAW         DEFAULT NULL,
                        p_iter     IN PLS_INTEGER DEFAULT NULL) RETURN VARCHAR2;

  -- pwd_verify_hex: 저장된 값과 비밀번호가 맞는지 확인합니다.
  --   p_password    사용자가 입력한 비밀번호.
  --   p_stored_hex  pwd_hash_hex 로 만든 값.
  -- 반환            맞으면 1, 아니면 0. 인자가 NULL 이거나 저장값이 깨져 있어도 0 이며,
  --                 잘못된 입력에 대해 오류를 던지지 않습니다.
  FUNCTION pwd_verify_hex(p_password IN VARCHAR2, p_stored_hex IN VARCHAR2) RETURN NUMBER;

  -- ===== 키 관리 (소유 계정으로 실행, 호출마다 커밋) =======================

  -- init_key: 첫 키를 만듭니다. 설치 직후 한 번만 실행합니다 (30_init_key.sql).
  --           끝나면 데이터베이스를 백업하십시오.
  -- 오류      -20605 이미 키가 있음.
  PROCEDURE init_key;

  -- rotate_key: 새 키를 쓰기 시작합니다. 이전 키는 남겨 두어 기존 자료를 계속 복호화합니다.
  --             기존 자료는 다시 암호화하기 전까지 이전 키를 그대로 씁니다 (안내서 제6장).
  -- 오류        -20605 아직 키가 없음.
  PROCEDURE rotate_key;

  -- is_ready: 지금 암호화를 쓸 수 있으면 1, 아니면 0. 오류를 던지지 않습니다.
  --           감시에 쓰기 알맞습니다.
  FUNCTION  is_ready RETURN NUMBER;

  -- ===== 시험용 =============================================================
  -- 50_selftest.sql 만 사용합니다. 응용에서 쓰지 마십시오.
  FUNCTION derive(p_root IN RAW, p_label IN VARCHAR2) RETURN RAW;
  FUNCTION pack_with_root(p_root IN RAW, p_key_id IN PLS_INTEGER,
                          p_plain IN VARCHAR2, p_iv IN RAW DEFAULT NULL) RETURN RAW;
  FUNCTION unpack_with_root(p_root IN RAW, p_blob IN RAW) RETURN VARCHAR2;
  FUNCTION wrap_root(p_root IN RAW, p_seal IN RAW, p_iv IN RAW DEFAULT NULL) RETURN RAW;
  FUNCTION unwrap_root(p_blob IN RAW, p_seal IN RAW) RETURN RAW;
END PKG_SFC;
/

CREATE OR REPLACE PACKAGE BODY PKG_SFC AS

  c_charset  CONSTANT VARCHAR2(30) := 'AL32UTF8';
  c_fmt_ver  CONSTANT PLS_INTEGER := 1;
  c_alg_aes  CONSTANT PLS_INTEGER := 1;
  c_iv_len   CONSTANT PLS_INTEGER := 16;
  c_tag_len  CONSTANT PLS_INTEGER := 32;
  c_hdr_len  CONSTANT PLS_INTEGER := 4;
  c_min_len  CONSTANT PLS_INTEGER := 68;     -- 헤더 4 + IV 16 + 암호 블록 1개 16 + 태그 32
  c_max_blob CONSTANT PLS_INTEGER := 2000;   -- 16진 문자열이 4000자 안에 들어가야 합니다
  c_max_plain CONSTANT PLS_INTEGER := 1900;  -- 평문 바이트 수. 헤더, 패딩, 태그가 들어갈 자리를 남긴 값입니다
  c_aes      CONSTANT PLS_INTEGER :=
    DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5;

  c_kdf_ver       CONSTANT PLS_INTEGER := 1;
  c_kdf_pbkdf2    CONSTANT PLS_INTEGER := 1;
  c_pwd_salt_len  CONSTANT PLS_INTEGER := 16;
  c_pwd_dk_len    CONSTANT PLS_INTEGER := 32;
  c_pwd_blob_len  CONSTANT PLS_INTEGER := 54;   -- 2 + 4 + 16 + 32

  c_lbl_enc      CONSTANT VARCHAR2(30) := 'OCS-LITE/ENC/v1';
  c_lbl_mac      CONSTANT VARCHAR2(30) := 'OCS-LITE/MAC/v1';
  c_lbl_seal_enc CONSTANT VARCHAR2(30) := 'OCS-LITE/SEAL-ENC/v1';
  c_lbl_seal_mac CONSTANT VARCHAR2(30) := 'OCS-LITE/SEAL-MAC/v1';

  TYPE t_keys IS RECORD (enc_key RAW(32), mac_key RAW(32));
  TYPE t_key_cache IS TABLE OF t_keys INDEX BY PLS_INTEGER;
  g_cache t_key_cache;   -- 키 번호별로 유도한 키. 세션이 끝나면 사라집니다

  PROCEDURE fail(p_code IN PLS_INTEGER, p_msg IN VARCHAR2) IS
  BEGIN
    RAISE_APPLICATION_ERROR(p_code, p_msg);
  END fail;

  -- 바이트 도우미 -----------------------------------------------------------
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

  -- 1~4바이트 빅엔디언 부호 없는 정수
  FUNCTION int_of(p_r IN RAW) RETURN PLS_INTEGER IS
    v_len PLS_INTEGER := NVL(UTL_RAW.LENGTH(p_r), 0);
  BEGIN
    IF v_len = 0 THEN
      RETURN 0;
    ELSIF v_len >= 4 THEN
      RETURN UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(p_r, v_len - 3, 4));
    END IF;
    RETURN UTL_RAW.CAST_TO_BINARY_INTEGER(
             UTL_RAW.CONCAT(UTL_RAW.COPIES(HEXTORAW('00'), 4 - v_len), p_r));
  END int_of;

  -- 길이가 같은 두 값을 끝까지 비교합니다. 처음 다른 곳에서 멈추지 않습니다
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

  FUNCTION to_utf8(p_s IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN UTL_I18N.STRING_TO_RAW(p_s, c_charset);
  END to_utf8;

  FUNCTION from_utf8(p_r IN RAW) RETURN VARCHAR2 IS
  BEGIN
    RETURN UTL_I18N.RAW_TO_CHAR(p_r, c_charset);
  END from_utf8;

  FUNCTION hex_to_raw(p_hex IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN HEXTORAW(p_hex);
  EXCEPTION
    WHEN OTHERS THEN
      fail(e_bad_format, 'not a valid hex string');
      RETURN NULL;
  END hex_to_raw;

  FUNCTION hmac(p_msg IN RAW, p_key IN RAW) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.MAC(src => p_msg, typ => DBMS_CRYPTO.HMAC_SH256, key => p_key);
  END hmac;

  FUNCTION derive(p_root IN RAW, p_label IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN hmac(UTL_RAW.CAST_TO_RAW(p_label), p_root);
  END derive;

  -- 암호문 ---------------------------------------------------------------------
  FUNCTION pack_raw(p_plain IN RAW, p_key_id IN PLS_INTEGER,
                    p_enc_key IN RAW, p_mac_key IN RAW, p_iv IN RAW) RETURN RAW IS
    v_iv     RAW(16);
    v_ct     RAW(32767);
    v_signed RAW(32767);
  BEGIN
    IF p_key_id IS NULL OR p_key_id < 0 OR p_key_id > 65535 THEN
      fail(e_bad_arg, 'key id out of range');
    END IF;
    v_iv := NVL(p_iv, DBMS_CRYPTO.RANDOMBYTES(c_iv_len));
    IF UTL_RAW.LENGTH(v_iv) <> c_iv_len THEN
      fail(e_bad_arg, 'iv must be 16 bytes');
    END IF;
    v_ct := DBMS_CRYPTO.ENCRYPT(src => p_plain, typ => c_aes, key => p_enc_key, iv => v_iv);
    v_signed := UTL_RAW.CONCAT(byte_of(c_fmt_ver), byte_of(c_alg_aes),
                               word_of(p_key_id), v_iv, v_ct);
    RETURN UTL_RAW.CONCAT(v_signed, hmac(v_signed, p_mac_key));
  END pack_raw;

  PROCEDURE check_blob(p_blob IN RAW) IS
  BEGIN
    IF p_blob IS NULL OR UTL_RAW.LENGTH(p_blob) < c_min_len THEN
      fail(e_bad_format, 'ciphertext too short');
    END IF;
    IF int_of(UTL_RAW.SUBSTR(p_blob, 1, 1)) <> c_fmt_ver
       OR int_of(UTL_RAW.SUBSTR(p_blob, 2, 1)) <> c_alg_aes THEN
      fail(e_bad_format, 'unknown ciphertext version or algorithm');
    END IF;
  END check_blob;

  FUNCTION unpack_raw(p_blob IN RAW, p_enc_key IN RAW, p_mac_key IN RAW) RETURN RAW IS
    v_len    PLS_INTEGER;
    v_signed RAW(32767);
    v_tag    RAW(32);
    v_iv     RAW(16);
    v_ct     RAW(32767);
  BEGIN
    check_blob(p_blob);
    v_len    := UTL_RAW.LENGTH(p_blob);
    v_signed := UTL_RAW.SUBSTR(p_blob, 1, v_len - c_tag_len);
    v_tag    := UTL_RAW.SUBSTR(p_blob, v_len - c_tag_len + 1, c_tag_len);
    -- 태그 검증이 먼저입니다. 실패하면 복호화를 시도하지 않습니다
    IF NOT const_eq(hmac(v_signed, p_mac_key), v_tag) THEN
      fail(e_integrity, 'integrity check failed');
    END IF;
    v_iv := UTL_RAW.SUBSTR(p_blob, c_hdr_len + 1, c_iv_len);
    v_ct := UTL_RAW.SUBSTR(p_blob, c_hdr_len + c_iv_len + 1,
                           v_len - c_tag_len - c_hdr_len - c_iv_len);
    RETURN DBMS_CRYPTO.DECRYPT(src => v_ct, typ => c_aes, key => p_enc_key, iv => v_iv);
  END unpack_raw;

  -- 시험용 / 봉인값 감싸기 -------------------------------------------------
  FUNCTION pack_with_root(p_root IN RAW, p_key_id IN PLS_INTEGER,
                          p_plain IN VARCHAR2, p_iv IN RAW DEFAULT NULL) RETURN RAW IS
  BEGIN
    RETURN pack_raw(to_utf8(p_plain), p_key_id,
                    derive(p_root, c_lbl_enc), derive(p_root, c_lbl_mac), p_iv);
  END pack_with_root;

  FUNCTION unpack_with_root(p_root IN RAW, p_blob IN RAW) RETURN VARCHAR2 IS
  BEGIN
    RETURN from_utf8(unpack_raw(p_blob, derive(p_root, c_lbl_enc), derive(p_root, c_lbl_mac)));
  END unpack_with_root;

  FUNCTION wrap_root(p_root IN RAW, p_seal IN RAW, p_iv IN RAW DEFAULT NULL) RETURN RAW IS
  BEGIN
    RETURN pack_raw(p_root, 0, derive(p_seal, c_lbl_seal_enc), derive(p_seal, c_lbl_seal_mac), p_iv);
  END wrap_root;

  FUNCTION unwrap_root(p_blob IN RAW, p_seal IN RAW) RETURN RAW IS
  BEGIN
    RETURN unpack_raw(p_blob, derive(p_seal, c_lbl_seal_enc), derive(p_seal, c_lbl_seal_mac));
  END unwrap_root;

  -- 키 -------------------------------------------------------------------------
  FUNCTION load_keys(p_key_id IN PLS_INTEGER) RETURN t_keys IS
    v_wrapped RAW(256);
    v_root    RAW(32);
    v         t_keys;
  BEGIN
    IF g_cache.EXISTS(p_key_id) THEN
      RETURN g_cache(p_key_id);
    END IF;
    BEGIN
      SELECT root_wrapped INTO v_wrapped FROM SFC_KEY WHERE key_id = p_key_id;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        fail(e_no_key, 'key id not found: ' || p_key_id);
    END;
    BEGIN
      v_root := unwrap_root(v_wrapped, SFC_SEAL.get_seal);
    EXCEPTION
      WHEN OTHERS THEN
        IF SQLCODE = e_integrity THEN
          fail(e_no_key, 'stored key does not match the seal');
        END IF;
        RAISE;
    END;
    v.enc_key := derive(v_root, c_lbl_enc);
    v.mac_key := derive(v_root, c_lbl_mac);
    g_cache(p_key_id) := v;
    RETURN v;
  END load_keys;

  FUNCTION active_key_id RETURN PLS_INTEGER IS
    v PLS_INTEGER;
  BEGIN
    SELECT key_id INTO v FROM SFC_KEY WHERE key_state = 'ACTIVE';
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      fail(e_no_key, 'no active key, run PKG_SFC.init_key');
      RETURN NULL;
  END active_key_id;

  PROCEDURE new_key IS
    v_root RAW(32) := DBMS_CRYPTO.RANDOMBYTES(32);
  BEGIN
    INSERT INTO SFC_KEY (key_id, key_state, root_wrapped)
    VALUES (SFC_KEY_SEQ.NEXTVAL, 'ACTIVE', wrap_root(v_root, SFC_SEAL.get_seal));
    g_cache.DELETE;
  END new_key;

  PROCEDURE init_key IS
    v_n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO v_n FROM SFC_KEY;
    IF v_n > 0 THEN
      fail(e_state, 'keys already exist, use rotate_key');
    END IF;
    new_key;
    COMMIT;
  END init_key;

  PROCEDURE rotate_key IS
    v_n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO v_n FROM SFC_KEY WHERE key_state = 'ACTIVE';
    IF v_n = 0 THEN
      fail(e_state, 'no active key, use init_key');
    END IF;
    -- 이전 키는 OLD 상태로 남겨 기존 자료를 계속 복호화합니다
    UPDATE SFC_KEY SET key_state = 'OLD', retired_at = SYSTIMESTAMP
     WHERE key_state = 'ACTIVE';
    new_key;
    COMMIT;
  END rotate_key;

  FUNCTION is_ready RETURN NUMBER IS
    v t_keys;
  BEGIN
    v := load_keys(active_key_id);
    RETURN 1;
  EXCEPTION
    WHEN OTHERS THEN
      RETURN 0;
  END is_ready;

  -- 양방향 ------------------------------------------------------------------------
  FUNCTION encrypt_hex(p_plain IN VARCHAR2, p_iv IN RAW DEFAULT NULL) RETURN VARCHAR2 IS
    v_id    PLS_INTEGER;
    v_keys  t_keys;
    v_plain RAW(32767);
  BEGIN
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    v_plain := to_utf8(p_plain);
    IF UTL_RAW.LENGTH(v_plain) > c_max_plain THEN
      fail(e_bad_arg, 'plaintext too long');
    END IF;
    v_id   := active_key_id;
    v_keys := load_keys(v_id);
    RETURN RAWTOHEX(pack_raw(v_plain, v_id, v_keys.enc_key, v_keys.mac_key, p_iv));
  END encrypt_hex;

  FUNCTION decrypt_hex(p_hex IN VARCHAR2) RETURN VARCHAR2 IS
    v_blob RAW(32767);
    v_keys t_keys;
  BEGIN
    IF p_hex IS NULL THEN
      RETURN NULL;
    END IF;
    v_blob := hex_to_raw(p_hex);
    check_blob(v_blob);
    -- 헤더의 키 번호로 어느 키로 만든 값인지 알 수 있어, 키를 교체해도 기존 자료를 읽을 수 있습니다
    v_keys := load_keys(int_of(UTL_RAW.SUBSTR(v_blob, 3, 2)));
    RETURN from_utf8(unpack_raw(v_blob, v_keys.enc_key, v_keys.mac_key));
  END decrypt_hex;

  FUNCTION mask_value(p_plain IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2 IS
    v_type   VARCHAR2(10) := UPPER(NVL(p_type, 'ALL'));
    v_digits VARCHAR2(4000);
    v_len    PLS_INTEGER;
  BEGIN
    IF v_type NOT IN ('RRN', 'ACCOUNT', 'ALL') THEN
      fail(e_bad_arg, 'mask type must be RRN, ACCOUNT or ALL');
    END IF;
    IF p_plain IS NULL THEN
      RETURN NULL;
    END IF;
    IF v_type = 'RRN' THEN
      -- 13자리: 앞 여섯 자리만 남기고 뒤 일곱 자리를 가립니다
      v_digits := REGEXP_REPLACE(p_plain, '[^0-9]', '');
      IF LENGTH(v_digits) = 13 THEN
        RETURN SUBSTR(v_digits, 1, 6) || '-*******';
      END IF;
    ELSIF v_type = 'ACCOUNT' THEN
      -- 앞 네 글자만 남깁니다
      v_len := LENGTH(p_plain);
      IF v_len > 4 THEN
        RETURN SUBSTR(p_plain, 1, 4) || RPAD('*', v_len - 4, '*');
      END IF;
    END IF;
    RETURN '********';
  END mask_value;

  FUNCTION mask_hex(p_hex IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2 IS
  BEGIN
    RETURN mask_value(decrypt_hex(p_hex), p_type);
  END mask_hex;

  -- 일방향 --------------------------------------------------------------------------
  FUNCTION pbkdf2_sha256(p_password IN RAW, p_salt IN RAW, p_iterations IN PLS_INTEGER) RETURN RAW IS
    v_u RAW(32);
    v_t RAW(32);
  BEGIN
    -- 출력 길이가 해시 길이와 같아 블록이 하나뿐입니다
    v_u := hmac(UTL_RAW.CONCAT(p_salt, HEXTORAW('00000001')), p_password);
    v_t := v_u;
    FOR i IN 2 .. p_iterations LOOP
      v_u := hmac(v_u, p_password);
      v_t := UTL_RAW.BIT_XOR(v_t, v_u);
    END LOOP;
    RETURN v_t;
  END pbkdf2_sha256;

  FUNCTION pwd_hash_hex(p_password IN VARCHAR2,
                        p_salt     IN RAW         DEFAULT NULL,
                        p_iter     IN PLS_INTEGER DEFAULT NULL) RETURN VARCHAR2 IS
    v_salt RAW(16);
    v_iter PLS_INTEGER;
  BEGIN
    -- 오라클은 빈 문자열을 NULL 로 다루므로 빈 비밀번호도 여기서 걸러집니다
    IF p_password IS NULL THEN
      fail(e_bad_arg, 'empty password is not allowed');
    END IF;
    v_salt := NVL(p_salt, DBMS_CRYPTO.RANDOMBYTES(c_pwd_salt_len));
    v_iter := NVL(p_iter, c_pwd_iterations);
    IF v_iter < 1 THEN
      fail(e_bad_arg, 'iterations must be at least 1');
    END IF;
    IF UTL_RAW.LENGTH(v_salt) <> c_pwd_salt_len THEN
      fail(e_bad_arg, 'salt must be 16 bytes');
    END IF;
    RETURN RAWTOHEX(UTL_RAW.CONCAT(
             byte_of(c_kdf_ver), byte_of(c_kdf_pbkdf2), dword_of(v_iter), v_salt,
             pbkdf2_sha256(to_utf8(p_password), v_salt, v_iter)));
  END pwd_hash_hex;

  FUNCTION pwd_verify_hex(p_password IN VARCHAR2, p_stored_hex IN VARCHAR2) RETURN NUMBER IS
    v_stored RAW(64);
    v_iter   PLS_INTEGER;
    v_salt   RAW(16);
    v_dk     RAW(32);
  BEGIN
    IF p_password IS NULL OR p_stored_hex IS NULL THEN
      RETURN 0;
    END IF;
    -- 형식이 깨진 저장값은 오류가 아니라 불일치로 처리합니다
    BEGIN
      v_stored := HEXTORAW(p_stored_hex);
    EXCEPTION
      WHEN OTHERS THEN
        RETURN 0;
    END;
    IF UTL_RAW.LENGTH(v_stored) <> c_pwd_blob_len
       OR int_of(UTL_RAW.SUBSTR(v_stored, 1, 1)) <> c_kdf_ver
       OR int_of(UTL_RAW.SUBSTR(v_stored, 2, 1)) <> c_kdf_pbkdf2 THEN
      RETURN 0;
    END IF;
    v_iter := int_of(UTL_RAW.SUBSTR(v_stored, 3, 4));
    IF v_iter < 1 THEN
      RETURN 0;
    END IF;
    v_salt := UTL_RAW.SUBSTR(v_stored, 7, c_pwd_salt_len);
    v_dk   := UTL_RAW.SUBSTR(v_stored, 7 + c_pwd_salt_len, c_pwd_dk_len);
    IF const_eq(pbkdf2_sha256(to_utf8(p_password), v_salt, v_iter), v_dk) THEN
      RETURN 1;
    END IF;
    RETURN 0;
  END pwd_verify_hex;

END PKG_SFC;
/

SELECT object_name, object_type, status FROM user_objects
 WHERE object_name = 'PKG_SFC' ORDER BY object_type;
SHOW ERRORS
