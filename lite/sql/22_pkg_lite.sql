-- OCS-LITE step 4 (run as SFC_OWNER)
--
-- PKG_LITE: the whole module in one package.
--
-- Blob layout (same as the full edition, so data can move between them):
--   ver(1) | alg(1) | key_id(2) | iv(16) | AES-256-CBC ciphertext | HMAC-SHA256 tag(32)
-- The tag covers everything before it. It is verified before decrypting.
-- Strings are always UTF-8 regardless of the database character set.
-- Stored form is the upper-case hex of the blob: a 13-char value gives 136 hex chars.
--
-- Nobody but the owner is granted this package. Applications call the FN_SFC_*
-- functions of 23_functions.sql, which are the only entry points.
--
-- Errors (all raised, never swallowed):
--   -20601 bad argument      -20602 key not ready / seal mismatch
--   -20603 integrity failed  -20604 bad ciphertext format
--   -20605 wrong state (init_key twice, rotate_key without a key)

CREATE OR REPLACE PACKAGE PKG_LITE AS

  e_bad_arg    CONSTANT PLS_INTEGER := -20601;
  e_no_key     CONSTANT PLS_INTEGER := -20602;
  e_integrity  CONSTANT PLS_INTEGER := -20603;
  e_bad_format CONSTANT PLS_INTEGER := -20604;
  e_state      CONSTANT PLS_INTEGER := -20605;

  -- PBKDF2 rounds for new password hashes. The value is stored inside each hash,
  -- so it can be raised later without invalidating existing hashes.
  c_pwd_iterations CONSTANT PLS_INTEGER := 10000;

  -- Two-way (identification numbers) --------------------------------------
  -- p_iv is for fixed test vectors only. Leave it NULL in real use.
  FUNCTION encrypt_hex(p_plain IN VARCHAR2, p_iv IN RAW DEFAULT NULL) RETURN VARCHAR2;
  FUNCTION decrypt_hex(p_hex   IN VARCHAR2) RETURN VARCHAR2;
  -- p_type: RRN | ACCOUNT | ALL
  FUNCTION mask_hex(p_hex IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2;
  FUNCTION mask_value(p_plain IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2;

  -- One-way (passwords) ---------------------------------------------------
  FUNCTION pwd_hash_hex(p_password IN VARCHAR2,
                        p_salt     IN RAW         DEFAULT NULL,
                        p_iter     IN PLS_INTEGER DEFAULT NULL) RETURN VARCHAR2;
  FUNCTION pwd_verify_hex(p_password IN VARCHAR2, p_stored_hex IN VARCHAR2) RETURN NUMBER;

  -- Key management (owner only, commits) ----------------------------------
  PROCEDURE init_key;
  PROCEDURE rotate_key;
  FUNCTION  is_ready RETURN NUMBER;   -- 1 when an active key can be loaded, else 0

  -- Test hooks, used by 50_selftest.sql ------------------------------------
  FUNCTION derive(p_root IN RAW, p_label IN VARCHAR2) RETURN RAW;
  FUNCTION pack_with_root(p_root IN RAW, p_key_id IN PLS_INTEGER,
                          p_plain IN VARCHAR2, p_iv IN RAW DEFAULT NULL) RETURN RAW;
  FUNCTION unpack_with_root(p_root IN RAW, p_blob IN RAW) RETURN VARCHAR2;
  FUNCTION wrap_root(p_root IN RAW, p_seal IN RAW, p_iv IN RAW DEFAULT NULL) RETURN RAW;
  FUNCTION unwrap_root(p_blob IN RAW, p_seal IN RAW) RETURN RAW;
END PKG_LITE;
/

CREATE OR REPLACE PACKAGE BODY PKG_LITE AS

  c_charset  CONSTANT VARCHAR2(30) := 'AL32UTF8';
  c_fmt_ver  CONSTANT PLS_INTEGER := 1;
  c_alg_aes  CONSTANT PLS_INTEGER := 1;
  c_iv_len   CONSTANT PLS_INTEGER := 16;
  c_tag_len  CONSTANT PLS_INTEGER := 32;
  c_hdr_len  CONSTANT PLS_INTEGER := 4;
  c_min_len  CONSTANT PLS_INTEGER := 68;     -- hdr 4 + iv 16 + one block 16 + tag 32
  c_max_blob CONSTANT PLS_INTEGER := 2000;   -- a hex string must fit in 4000 chars
  c_max_plain CONSTANT PLS_INTEGER := 1900;  -- plaintext bytes, leaves room for header, padding, tag
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
  g_cache t_key_cache;   -- derived keys per key id, kept for the session only

  PROCEDURE fail(p_code IN PLS_INTEGER, p_msg IN VARCHAR2) IS
  BEGIN
    RAISE_APPLICATION_ERROR(p_code, p_msg);
  END fail;

  -- byte helpers -----------------------------------------------------------
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

  -- big-endian unsigned integer from 1 to 4 bytes
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

  -- equal-length comparison that does not stop at the first difference
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

  -- blob ---------------------------------------------------------------------
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
    -- verify first: a failed tag means no decryption is attempted
    IF NOT const_eq(hmac(v_signed, p_mac_key), v_tag) THEN
      fail(e_integrity, 'integrity check failed');
    END IF;
    v_iv := UTL_RAW.SUBSTR(p_blob, c_hdr_len + 1, c_iv_len);
    v_ct := UTL_RAW.SUBSTR(p_blob, c_hdr_len + c_iv_len + 1,
                           v_len - c_tag_len - c_hdr_len - c_iv_len);
    RETURN DBMS_CRYPTO.DECRYPT(src => v_ct, typ => c_aes, key => p_enc_key, iv => v_iv);
  END unpack_raw;

  -- test hooks / seal wrapping -------------------------------------------------
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

  -- keys -------------------------------------------------------------------------
  FUNCTION load_keys(p_key_id IN PLS_INTEGER) RETURN t_keys IS
    v_wrapped RAW(256);
    v_root    RAW(32);
    v         t_keys;
  BEGIN
    IF g_cache.EXISTS(p_key_id) THEN
      RETURN g_cache(p_key_id);
    END IF;
    BEGIN
      SELECT root_wrapped INTO v_wrapped FROM LITE_KEY WHERE key_id = p_key_id;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        fail(e_no_key, 'key id not found: ' || p_key_id);
    END;
    BEGIN
      v_root := unwrap_root(v_wrapped, LITE_SEAL.get_seal);
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
    SELECT key_id INTO v FROM LITE_KEY WHERE key_state = 'ACTIVE';
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      fail(e_no_key, 'no active key, run PKG_LITE.init_key');
      RETURN NULL;
  END active_key_id;

  PROCEDURE new_key IS
    v_root RAW(32) := DBMS_CRYPTO.RANDOMBYTES(32);
  BEGIN
    INSERT INTO LITE_KEY (key_id, key_state, root_wrapped)
    VALUES (LITE_KEY_SEQ.NEXTVAL, 'ACTIVE', wrap_root(v_root, LITE_SEAL.get_seal));
    g_cache.DELETE;
  END new_key;

  PROCEDURE init_key IS
    v_n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO v_n FROM LITE_KEY;
    IF v_n > 0 THEN
      fail(e_state, 'keys already exist, use rotate_key');
    END IF;
    new_key;
    COMMIT;
  END init_key;

  PROCEDURE rotate_key IS
    v_n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO v_n FROM LITE_KEY WHERE key_state = 'ACTIVE';
    IF v_n = 0 THEN
      fail(e_state, 'no active key, use init_key');
    END IF;
    -- the old key stays (state OLD) so existing data still decrypts
    UPDATE LITE_KEY SET key_state = 'OLD', retired_at = SYSTIMESTAMP
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

  -- two-way ------------------------------------------------------------------------
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
    -- the header tells which key made this blob, which is what lets old data survive rotate_key
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
      -- 13 digits: keep the birth date part, hide the last seven
      v_digits := REGEXP_REPLACE(p_plain, '[^0-9]', '');
      IF LENGTH(v_digits) = 13 THEN
        RETURN SUBSTR(v_digits, 1, 6) || '-*******';
      END IF;
    ELSIF v_type = 'ACCOUNT' THEN
      -- keep the first four characters only
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

  -- one-way --------------------------------------------------------------------------
  FUNCTION pbkdf2_sha256(p_password IN RAW, p_salt IN RAW, p_iterations IN PLS_INTEGER) RETURN RAW IS
    v_u RAW(32);
    v_t RAW(32);
  BEGIN
    -- output length equals the hash length, so there is exactly one block
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
    -- NULL also covers the empty string, which Oracle treats as NULL
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
    -- a malformed stored value is a failed check, not an error
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

END PKG_LITE;
/

SELECT object_name, object_type, status FROM user_objects
 WHERE object_name = 'PKG_LITE' ORDER BY object_type;
SHOW ERRORS
