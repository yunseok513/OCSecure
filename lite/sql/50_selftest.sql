-- OCS-LITE self test (run as SFC_OWNER, after steps 1 to 6)
--
-- Part A needs no key and compares PKG_SFC with fixed vectors computed outside
-- Oracle by lite/tests/lite_ref.py (python test: lite/tests/test_lite_vectors.py).
-- Part B uses the live key and writes nothing to any table.
-- Any FAIL line means: do not deliver.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF

DECLARE
  g_pass PLS_INTEGER := 0;
  g_fail PLS_INTEGER := 0;

  k_root  CONSTANT RAW(32) := HEXTORAW('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
  k_seal  CONSTANT RAW(32) := HEXTORAW('202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F');
  k_iv    CONSTANT RAW(16) := HEXTORAW('A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0');
  k_iv2   CONSTANT RAW(16) := HEXTORAW('B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0');
  k_salt  CONSTANT RAW(16) := HEXTORAW('11111111111111111111111111111111');
  e_derive CONSTANT VARCHAR2(64) := '2E9709BDE42BD77BE97BF1B509048B0270119A8D8EEDE0AEBD19A1E7D20478AF';
  e_rrn    CONSTANT VARCHAR2(136) := '01010007A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A095E4DC8BA97A8662B744333E8FE73E5BE3A567AA061104951BDB23EBAA2A0C0960B9325DE81D2E29194B463B05BBA460';
  e_ko     CONSTANT VARCHAR2(136) := '01010007A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0FBC6B784924946CC8C3B6311E4E5408B6567F450217BB14960C4D69254206D14194CDD4E44B8C851C329BA288CFB9526';
  e_wrap   CONSTANT VARCHAR2(200) := '01010000B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0DBEAE3C657B45CD538F4D49BFDEBD011B741FD03FA40E718D88509732820932991EF0F7591681C435E77075565109DDFE0004C03A17545599BC27F6B1DFB2FF408CCCDCE2DECE3AF176D2877EB57B925';
  e_pwd    CONSTANT VARCHAR2(108) := '0101000000031111111111111111111111111111111122F66232ED11B2BE3A025C9A259FBC248C36680276200B28F94655B34C3D206B';

  v_ko   VARCHAR2(100);
  v_blob RAW(2000);
  v_hex  VARCHAR2(4000);
  v_hex2 VARCHAR2(4000);
  v_code NUMBER;

  PROCEDURE chk(p_name IN VARCHAR2, p_ok IN BOOLEAN) IS
  BEGIN
    IF p_ok THEN
      g_pass := g_pass + 1;
      DBMS_OUTPUT.PUT_LINE('PASS  ' || p_name);
    ELSE
      g_fail := g_fail + 1;
      DBMS_OUTPUT.PUT_LINE('FAIL  ' || p_name);
    END IF;
  END chk;

  -- runs a statement block and returns the error code it raises, 0 when none
  FUNCTION code_of(p_sql IN VARCHAR2) RETURN NUMBER IS
  BEGIN
    EXECUTE IMMEDIATE p_sql;
    RETURN 0;
  EXCEPTION
    WHEN OTHERS THEN
      RETURN SQLCODE;
  END code_of;
BEGIN
  v_ko := TO_CHAR(UNISTR('\D55C\AE00\D14C\C2A4\D2B8'));

  DBMS_OUTPUT.PUT_LINE('--- Part A: fixed vectors (no key needed)');
  chk('A1 key derivation', RAWTOHEX(PKG_SFC.derive(k_root, 'OCS-LITE/ENC/v1')) = e_derive);
  chk('A2 identification number blob',
      RAWTOHEX(PKG_SFC.pack_with_root(k_root, 7, '9001011234567', k_iv)) = e_rrn);
  chk('A3 Korean text blob (UTF-8)',
      RAWTOHEX(PKG_SFC.pack_with_root(k_root, 7, v_ko, k_iv)) = e_ko);
  chk('A4 root key wrap', RAWTOHEX(PKG_SFC.wrap_root(k_root, k_seal, k_iv2)) = e_wrap);
  chk('A5 root key unwrap', PKG_SFC.unwrap_root(HEXTORAW(e_wrap), k_seal) = k_root);
  chk('A6 password hash', PKG_SFC.pwd_hash_hex('!Pass-Word1', k_salt, 3) = e_pwd);
  chk('A7 blob round trip', PKG_SFC.unpack_with_root(k_root, HEXTORAW(e_ko)) = v_ko);
  chk('A8 length of a 13 char value is 136 hex chars', LENGTH(e_rrn) = 136);

  -- flip the last byte of the tag: must be refused before any decryption
  v_blob := HEXTORAW(e_rrn);
  v_blob := UTL_RAW.CONCAT(UTL_RAW.SUBSTR(v_blob, 1, UTL_RAW.LENGTH(v_blob) - 1),
                           UTL_RAW.BIT_XOR(UTL_RAW.SUBSTR(v_blob, UTL_RAW.LENGTH(v_blob), 1), HEXTORAW('01')));
  BEGIN
    v_ko := PKG_SFC.unpack_with_root(k_root, v_blob);
    v_code := 0;
  EXCEPTION
    WHEN OTHERS THEN v_code := SQLCODE;
  END;
  chk('A9 tampered tag is refused (-20603)', v_code = -20603);

  -- flip a ciphertext byte: the tag no longer matches
  v_blob := HEXTORAW(e_rrn);
  v_blob := UTL_RAW.CONCAT(UTL_RAW.SUBSTR(v_blob, 1, 20),
                           UTL_RAW.BIT_XOR(UTL_RAW.SUBSTR(v_blob, 21, 1), HEXTORAW('01')),
                           UTL_RAW.SUBSTR(v_blob, 22));
  BEGIN
    v_ko := PKG_SFC.unpack_with_root(k_root, v_blob);
    v_code := 0;
  EXCEPTION
    WHEN OTHERS THEN v_code := SQLCODE;
  END;
  chk('A10 tampered ciphertext is refused (-20603)', v_code = -20603);

  chk('A11 password verify (right)', PKG_SFC.pwd_verify_hex('!Pass-Word1', e_pwd) = 1);
  chk('A12 password verify (wrong)', PKG_SFC.pwd_verify_hex('!Pass-Word2', e_pwd) = 0);
  chk('A13 password verify (garbage stored value)', PKG_SFC.pwd_verify_hex('x', 'ZZ') = 0);
  chk('A14 password verify (NULL)', PKG_SFC.pwd_verify_hex(NULL, e_pwd) = 0);
  chk('A15 empty password refused (-20601)',
      code_of('BEGIN DBMS_OUTPUT.PUT(LENGTH(PKG_SFC.pwd_hash_hex(NULL))); END;') = -20601);

  chk('A16 mask RRN with hyphen', PKG_SFC.mask_value('900101-1234567', 'RRN') = '900101-*******');
  chk('A17 mask RRN without hyphen', PKG_SFC.mask_value('9001011234567', 'RRN') = '900101-*******');
  chk('A18 mask RRN of unexpected length hides all', PKG_SFC.mask_value('12345', 'RRN') = '********');
  chk('A19 mask ACCOUNT', PKG_SFC.mask_value('110123456789', 'ACCOUNT') = '1101********');
  chk('A20 mask ALL', PKG_SFC.mask_value('anything', 'ALL') = '********');
  chk('A21 mask NULL stays NULL', PKG_SFC.mask_value(NULL, 'RRN') IS NULL);
  chk('A22 unknown mask type refused (-20601)',
      code_of('BEGIN DBMS_OUTPUT.PUT(PKG_SFC.mask_value(''x'', ''ZZZ'')); END;') = -20601);

  DBMS_OUTPUT.PUT_LINE('--- Part B: live key');
  IF PKG_SFC.is_ready = 1 THEN
    v_hex := PKG_SFC.encrypt_hex('9001011234567');
    v_hex2 := PKG_SFC.encrypt_hex('9001011234567');
    chk('B1 stored form is 136 hex chars', LENGTH(v_hex) = 136);
    chk('B2 round trip', PKG_SFC.decrypt_hex(v_hex) = '9001011234567');
    chk('B3 same plain text gives different ciphertext', v_hex <> v_hex2);
    chk('B4 Korean round trip', PKG_SFC.decrypt_hex(PKG_SFC.encrypt_hex(TO_CHAR(UNISTR('\D55C\AE00')))) = TO_CHAR(UNISTR('\D55C\AE00')));
    chk('B5 NULL in, NULL out', PKG_SFC.encrypt_hex(NULL) IS NULL AND PKG_SFC.decrypt_hex(NULL) IS NULL);
    chk('B6 mask through ciphertext', PKG_SFC.mask_hex(v_hex, 'RRN') = '900101-*******');
    chk('B7 garbage ciphertext refused (-20604)',
        code_of('BEGIN DBMS_OUTPUT.PUT(PKG_SFC.decrypt_hex(''ZZ'')); END;') = -20604);
    chk('B8 too long plain text refused (-20601)',
        code_of('BEGIN DBMS_OUTPUT.PUT(PKG_SFC.encrypt_hex(RPAD(''a'', 3000, ''a''))); END;') = -20601);
    v_hex2 := PKG_SFC.pwd_hash_hex('MyPassw0rd!');
    chk('B9 password hash is 108 hex chars', LENGTH(v_hex2) = 108);
    chk('B10 password verify with default rounds',
        PKG_SFC.pwd_verify_hex('MyPassw0rd!', v_hex2) = 1 AND PKG_SFC.pwd_verify_hex('MyPassw0rd?', v_hex2) = 0);
    chk('B11 FN_SFC_READY', FN_SFC_READY = 1);
  ELSE
    DBMS_OUTPUT.PUT_LINE('SKIP  Part B: no usable key. Run 30_init_key.sql first.');
    g_fail := g_fail + 1;
  END IF;

  DBMS_OUTPUT.PUT_LINE('--- pass ' || g_pass || ', fail ' || g_fail);
  IF g_fail = 0 THEN
    DBMS_OUTPUT.PUT_LINE('OCS-LITE SELFTEST OK');
  ELSE
    DBMS_OUTPUT.PUT_LINE('OCS-LITE SELFTEST FAILED: do not deliver');
  END IF;
END;
/
