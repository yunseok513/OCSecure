-- OCS-LITE acceptance check T5: decrypt what T3 and T4 stored
--
-- Run as SFC_OWNER in a NEW session, after each of these events:
--   (a) the database was restarted,
--   (b) the database was restored from a backup (the restored copy, not the original),
--   (c) the package was recompiled and the session was reconnected.
-- Writes nothing. If the key table and the seal did not come along with the data, this
-- ends with ORA-20602 on the first row, which is the expected protection.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF
WHENEVER SQLERROR EXIT FAILURE

DECLARE
  v_rows NUMBER := 0;
  v_bad  NUMBER := 0;
  v_keys NUMBER;
BEGIN
  DBMS_OUTPUT.PUT_LINE('--- database ' || SYS_CONTEXT('USERENV', 'DB_NAME')
                       || ', instance ' || SYS_CONTEXT('USERENV', 'INSTANCE_NAME')
                       || ', now ' || TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'));
  SELECT COUNT(*) INTO v_keys FROM SFC_KEY;
  DBMS_OUTPUT.PUT_LINE('keys in SFC_KEY : ' || v_keys);
  DBMS_OUTPUT.PUT_LINE('FN_SFC_READY    : ' || PKG_SFC.is_ready);

  FOR r IN (SELECT id, phase, plain, enc FROM SFC_T_PERSIST ORDER BY id) LOOP
    v_rows := v_rows + 1;
    IF PKG_SFC.decrypt_hex(r.enc) = r.plain THEN
      DBMS_OUTPUT.PUT_LINE('PASS  row ' || r.id || ' (' || r.phase || ', key ' || SUBSTR(r.enc, 5, 4) || ')');
    ELSE
      v_bad := v_bad + 1;
      DBMS_OUTPUT.PUT_LINE('FAIL  row ' || r.id || ' (' || r.phase || ') decrypted to a different value');
    END IF;
  END LOOP;

  IF v_rows = 0 THEN
    RAISE_APPLICATION_ERROR(-20990, 'T5: SFC_T_PERSIST has no rows. Run T3 first.');
  END IF;
  IF v_bad > 0 OR PKG_SFC.is_ready <> 1 THEN
    RAISE_APPLICATION_ERROR(-20990, 'T5 failed: ' || v_bad || ' row(s) differ, ready=' || PKG_SFC.is_ready);
  END IF;
  DBMS_OUTPUT.PUT_LINE('T5 OK (' || v_rows || ' rows)');
END;
/
