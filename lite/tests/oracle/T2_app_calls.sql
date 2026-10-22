-- OCS-LITE acceptance check T2: the business schema can use the six functions and nothing else
--
-- Run as the BUSINESS SCHEMA that 40_connect_app.sql was run for (not as SFC_OWNER).
-- Writes nothing. The last four checks must be REFUSED by Oracle.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF
WHENEVER SQLERROR EXIT FAILURE

DECLARE
  g_pass PLS_INTEGER := 0;
  g_fail PLS_INTEGER := 0;
  v_hex  VARCHAR2(400);
  v_pwd  VARCHAR2(200);

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

  FUNCTION code_of(p_sql IN VARCHAR2) RETURN NUMBER IS
  BEGIN
    EXECUTE IMMEDIATE p_sql;
    RETURN 0;
  EXCEPTION
    WHEN OTHERS THEN
      RETURN SQLCODE;
  END code_of;
BEGIN
  DBMS_OUTPUT.PUT_LINE('--- running as ' || SYS_CONTEXT('USERENV', 'SESSION_USER'));
  chk('C1 FN_SFC_READY is 1', FN_SFC_READY = 1);
  v_hex := FN_SFC_ENC('9001011234567');
  chk('C2 encrypt then decrypt', FN_SFC_DEC(v_hex) = '9001011234567');
  chk('C3 mask RRN', FN_SFC_MASK(v_hex, 'RRN') = '900101-*******');
  chk('C4 mask ACCOUNT', FN_SFC_MASK(FN_SFC_ENC('110123456789'), 'ACCOUNT') = '1101********');
  chk('C5 mask type defaults to ALL', FN_SFC_MASK(v_hex) = '********');
  v_pwd := FN_SFC_PWD_HASH('pw-for-test');
  chk('C6 password hash is 108 characters', LENGTH(v_pwd) = 108);
  chk('C7 password verify (right)', FN_SFC_PWD_VERIFY('pw-for-test', v_pwd) = 1);
  chk('C8 password verify (wrong)', FN_SFC_PWD_VERIFY('other', v_pwd) = 0);

  DBMS_OUTPUT.PUT_LINE('--- these must be refused');
  chk('C9  the key table cannot be read (ORA-00942)',
      code_of('SELECT COUNT(*) FROM SFC_OWNER.SFC_KEY') = -942);
  chk('C10 PKG_SFC cannot be called',
      code_of('DECLARE n NUMBER; BEGIN n := SFC_OWNER.PKG_SFC.is_ready; END;') IN (-6550, -942));
  chk('C11 SFC_SEAL cannot be called',
      code_of('DECLARE r RAW(32); BEGIN r := SFC_OWNER.SFC_SEAL.get_seal; END;') IN (-6550, -942));
  chk('C12 init_key cannot be called',
      code_of('BEGIN SFC_OWNER.PKG_SFC.init_key; END;') IN (-6550, -942));

  DBMS_OUTPUT.PUT_LINE('--- pass ' || g_pass || ', fail ' || g_fail);
  IF g_fail > 0 THEN
    RAISE_APPLICATION_ERROR(-20990, 'T2 failed: ' || g_fail || ' check(s).');
  END IF;
  DBMS_OUTPUT.PUT_LINE('T2 OK');
END;
/
