-- OCS-LITE step 5 (run as SFC_OWNER)
--
-- The only entry points for applications. Each one is a thin call into PKG_LITE.
-- Applications get EXECUTE on these functions and on nothing else.
--
--   FN_SFC_ENC(plain)               identification number -> hex ciphertext (VARCHAR2)
--   FN_SFC_DEC(hex)                 hex ciphertext -> plain text
--   FN_SFC_MASK(hex, type)          masked text, type = RRN | ACCOUNT | ALL
--   FN_SFC_PWD_HASH(password)       password -> hex hash (VARCHAR2(108))
--   FN_SFC_PWD_VERIFY(pwd, hash)    1 when it matches, else 0
--   FN_SFC_READY                    1 when encryption is usable, else 0

CREATE OR REPLACE FUNCTION FN_SFC_ENC(p_plain IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.encrypt_hex(p_plain);
END FN_SFC_ENC;
/

CREATE OR REPLACE FUNCTION FN_SFC_DEC(p_hex IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.decrypt_hex(p_hex);
END FN_SFC_DEC;
/

CREATE OR REPLACE FUNCTION FN_SFC_MASK(p_hex IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.mask_hex(p_hex, p_type);
END FN_SFC_MASK;
/

CREATE OR REPLACE FUNCTION FN_SFC_PWD_HASH(p_password IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.pwd_hash_hex(p_password);
END FN_SFC_PWD_HASH;
/

CREATE OR REPLACE FUNCTION FN_SFC_PWD_VERIFY(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN NUMBER IS
BEGIN
  RETURN PKG_LITE.pwd_verify_hex(p_password, p_stored);
END FN_SFC_PWD_VERIFY;
/

CREATE OR REPLACE FUNCTION FN_SFC_READY RETURN NUMBER IS
BEGIN
  RETURN PKG_LITE.is_ready;
END FN_SFC_READY;
/

SELECT object_name, status FROM user_objects
 WHERE object_name LIKE 'FN\_SFC\_%' ESCAPE '\' AND object_type = 'FUNCTION'
 ORDER BY object_name;
