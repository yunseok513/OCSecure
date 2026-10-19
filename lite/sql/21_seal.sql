-- OCS-LITE step 3 (run as SFC_OWNER)
--
-- Creates package SFC_SEAL holding a random 32-byte seal that wraps the root keys
-- stored in SFC_KEY. It is generated once, here, and is NOT regenerated when
-- PKG_SFC is recompiled. Losing or replacing it makes every stored key
-- unreadable, so this script refuses to run a second time.
--
-- Optional hardening: wrap the generated source (Oracle "wrap" utility) before
-- delivery to hide the value from DBA_SOURCE. See the manual. It only hides the
-- value, it does not protect it from someone who has the whole database.

SET SERVEROUTPUT ON

CREATE OR REPLACE PACKAGE SFC_SEAL AS
  FUNCTION get_seal RETURN RAW;
END SFC_SEAL;
/

DECLARE
  v_exists NUMBER;
  v_hex    VARCHAR2(64);
BEGIN
  SELECT COUNT(*) INTO v_exists
    FROM user_objects
   WHERE object_name = 'SFC_SEAL' AND object_type = 'PACKAGE BODY';
  IF v_exists > 0 THEN
    DBMS_OUTPUT.PUT_LINE('SFC_SEAL body already exists. Left unchanged on purpose.');
    RETURN;
  END IF;
  v_hex := RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(32));
  EXECUTE IMMEDIATE
    'CREATE OR REPLACE PACKAGE BODY SFC_SEAL AS '
    || 'FUNCTION get_seal RETURN RAW IS BEGIN RETURN HEXTORAW(''' || v_hex
    || '''); END get_seal; END SFC_SEAL;';
  DBMS_OUTPUT.PUT_LINE('SFC_SEAL created.');
END;
/

SELECT object_name, object_type, status FROM user_objects WHERE object_name = 'SFC_SEAL';
