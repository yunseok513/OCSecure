-- OCS-LITE acceptance check T4: rotate the key; old and new ciphertext must both decrypt
--
-- TEST INSTANCE ONLY. Run as SFC_OWNER after T3. rotate_key CANNOT be undone: it adds a
-- key that stays in SFC_KEY for good. Running this on a production database is a mistake.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF
WHENEVER SQLERROR EXIT FAILURE

PROMPT --- keys before
SELECT key_id, key_state FROM SFC_KEY ORDER BY key_id;

DECLARE
  g_pass       PLS_INTEGER := 0;
  g_fail       PLS_INTEGER := 0;
  v_old_active NUMBER;
  v_new_active NUMBER;
  v_active_cnt NUMBER;
  v_id         NUMBER;
  v_bad        NUMBER := 0;
  v_n          NUMBER;

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
BEGIN
  SELECT key_id INTO v_old_active FROM SFC_KEY WHERE key_state = 'ACTIVE';
  PKG_SFC.rotate_key;
  SELECT key_id INTO v_new_active FROM SFC_KEY WHERE key_state = 'ACTIVE';
  SELECT COUNT(*) INTO v_active_cnt FROM SFC_KEY WHERE key_state = 'ACTIVE';

  SELECT NVL(MAX(id), 0) + 1 INTO v_id FROM SFC_T_PERSIST;
  INSERT INTO SFC_T_PERSIST VALUES (v_id, 'after-rotation', '9001011234999',
                                    PKG_SFC.encrypt_hex('9001011234999'));
  COMMIT;

  chk('R1 exactly one ACTIVE key', v_active_cnt = 1);
  chk('R2 the new key number is higher (' || v_old_active || ' -> ' || v_new_active || ')',
      v_new_active > v_old_active);
  -- PL/SQL does not allow a subquery inside an expression, so each count goes into a variable first
  SELECT COUNT(*) INTO v_n FROM SFC_KEY WHERE key_id = v_old_active AND key_state = 'OLD';
  chk('R3 the previous key is now OLD', v_n = 1);
  SELECT COUNT(*) INTO v_n FROM SFC_T_PERSIST
   WHERE id = v_id AND TO_NUMBER(SUBSTR(enc, 5, 4), 'XXXX') = v_new_active;
  chk('R4 new ciphertext carries the new key number', v_n = 1);
  SELECT COUNT(*) INTO v_n FROM SFC_T_PERSIST
   WHERE phase = 'before-rotation' AND TO_NUMBER(SUBSTR(enc, 5, 4), 'XXXX') >= v_new_active;
  chk('R5 earlier ciphertext still carries an older key number', v_n = 0);

  FOR r IN (SELECT id, plain, enc FROM SFC_T_PERSIST ORDER BY id) LOOP
    IF PKG_SFC.decrypt_hex(r.enc) <> r.plain THEN
      v_bad := v_bad + 1;
      DBMS_OUTPUT.PUT_LINE('      row ' || r.id || ' did not decrypt to the stored plain text');
    END IF;
  END LOOP;
  chk('R6 every stored row (old key and new key) decrypts to its plain text', v_bad = 0);

  DBMS_OUTPUT.PUT_LINE('--- pass ' || g_pass || ', fail ' || g_fail);
  IF g_fail > 0 THEN
    RAISE_APPLICATION_ERROR(-20990, 'T4 failed: ' || g_fail || ' check(s).');
  END IF;
  DBMS_OUTPUT.PUT_LINE('T4 OK');
END;
/

PROMPT --- keys after
SELECT key_id, key_state FROM SFC_KEY ORDER BY key_id;
PROMPT --- stored rows
SELECT id, phase, SUBSTR(enc, 5, 4) AS key_hex FROM SFC_T_PERSIST ORDER BY id;
