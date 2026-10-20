-- OCS-LITE step 5 (run as SFC_OWNER)
--
-- The functions applications call. A business schema gets EXECUTE on these six
-- functions and nothing else (40_connect_app.sql); after that it can use them
-- without a prefix:
--
--   INSERT INTO member (rrn_enc, pw_hash)
--   VALUES (FN_SFC_ENC('9001011234567'), FN_SFC_PWD_HASH('password typed by the user'));
--
--   SELECT FN_SFC_DEC(rrn_enc), FN_SFC_MASK(rrn_enc, 'RRN') FROM member;
--   SELECT FN_SFC_PWD_VERIFY('password typed by the user', pw_hash) FROM member;
--
-- Errors are raised as ORA-206xx; see the manual, chapter 7.

-- FN_SFC_ENC: encrypt an identification number (resident registration number, account number).
--   p_plain  the text. NULL in, NULL out. At most 1900 bytes in UTF-8.
-- Returns    hex string for a VARCHAR2 column (136 characters for 13 characters of input).
--            A different value on every call, so it cannot be used in a WHERE condition.
-- Raises     -20601 text too long, -20602 no usable key.
CREATE OR REPLACE FUNCTION FN_SFC_ENC(p_plain IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.encrypt_hex(p_plain);
END FN_SFC_ENC;
/

-- FN_SFC_DEC: get the original text back from a value made by FN_SFC_ENC.
--   p_hex    the stored value. NULL in, NULL out.
-- Returns    the original text. Do not write it to logs, temporary tables or open views.
-- Raises     -20604 not a value of this module (check the column length), -20603 altered value,
--            -20602 key not found.
CREATE OR REPLACE FUNCTION FN_SFC_DEC(p_hex IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.decrypt_hex(p_hex);
END FN_SFC_DEC;
/

-- FN_SFC_MASK: show a stored value with part of it hidden, without exposing the whole text.
--   p_hex    the stored value. NULL in, NULL out.
--   p_type   RRN      900101-*******  (13 digits; any other length: ********)
--            ACCOUNT  first 4 characters shown, the rest *
--            ALL      ********       (default)
-- Raises     -20601 unknown p_type, plus the errors of FN_SFC_DEC.
CREATE OR REPLACE FUNCTION FN_SFC_MASK(p_hex IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.mask_hex(p_hex, p_type);
END FN_SFC_MASK;
/

-- FN_SFC_PWD_HASH: make the value to store for a password. It cannot be reversed.
--   p_password  the password. NULL or empty is refused.
-- Returns       108-character hex string. A different value on every call for the same password.
-- Raises        -20601 empty password.
-- Note          Each call takes noticeable time on purpose. Measure it after installation (manual, 4.2).
CREATE OR REPLACE FUNCTION FN_SFC_PWD_HASH(p_password IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.pwd_hash_hex(p_password);
END FN_SFC_PWD_HASH;
/

-- FN_SFC_PWD_VERIFY: check a password against the value stored by FN_SFC_PWD_HASH.
--   p_password  the password the user typed.
--   p_stored    the stored value.
-- Returns       1 when it matches, otherwise 0. Bad or NULL input gives 0, not an error.
CREATE OR REPLACE FUNCTION FN_SFC_PWD_VERIFY(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN NUMBER IS
BEGIN
  RETURN PKG_SFC.pwd_verify_hex(p_password, p_stored);
END FN_SFC_PWD_VERIFY;
/

-- FN_SFC_READY: 1 when encryption can be used right now, otherwise 0. Never raises.
--               Use it for monitoring: SELECT FN_SFC_READY FROM DUAL;
CREATE OR REPLACE FUNCTION FN_SFC_READY RETURN NUMBER IS
BEGIN
  RETURN PKG_SFC.is_ready;
END FN_SFC_READY;
/

SELECT object_name, status FROM user_objects
 WHERE object_name LIKE 'FN\_SFC\_%' ESCAPE '\' AND object_type = 'FUNCTION'
 ORDER BY object_name;
