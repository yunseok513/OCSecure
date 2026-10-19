-- OCS-LITE step 5 (run as LITE_OWNER)
--
-- The only entry points for applications. Each one is a thin call into PKG_LITE.
-- Applications get EXECUTE on these functions and on nothing else.
--
--   LITE_ENC(plain)               identification number -> hex ciphertext (VARCHAR2)
--   LITE_DEC(hex)                 hex ciphertext -> plain text
--   LITE_MASK(hex, type)          masked text, type = RRN | ACCOUNT | ALL
--   LITE_PWD_HASH(password)       password -> hex hash (VARCHAR2(108))
--   LITE_PWD_VERIFY(pwd, hash)    1 when it matches, else 0
--   LITE_READY                    1 when encryption is usable, else 0

CREATE OR REPLACE FUNCTION LITE_ENC(p_plain IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.encrypt_hex(p_plain);
END LITE_ENC;
/

CREATE OR REPLACE FUNCTION LITE_DEC(p_hex IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.decrypt_hex(p_hex);
END LITE_DEC;
/

CREATE OR REPLACE FUNCTION LITE_MASK(p_hex IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.mask_hex(p_hex, p_type);
END LITE_MASK;
/

CREATE OR REPLACE FUNCTION LITE_PWD_HASH(p_password IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_LITE.pwd_hash_hex(p_password);
END LITE_PWD_HASH;
/

CREATE OR REPLACE FUNCTION LITE_PWD_VERIFY(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN NUMBER IS
BEGIN
  RETURN PKG_LITE.pwd_verify_hex(p_password, p_stored);
END LITE_PWD_VERIFY;
/

CREATE OR REPLACE FUNCTION LITE_READY RETURN NUMBER IS
BEGIN
  RETURN PKG_LITE.is_ready;
END LITE_READY;
/

SELECT object_name, status FROM user_objects
 WHERE object_name LIKE 'LITE\_%' ESCAPE '\' AND object_type = 'FUNCTION'
 ORDER BY object_name;
