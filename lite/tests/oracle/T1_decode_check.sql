-- OCS-LITE acceptance check T1: the conversion check query of manual section 4.3
--
-- TEST INSTANCE ONLY. Run as SFC_OWNER. Creates and drops its own table SFC_T_DECODE.
-- Five rows cover every NULL combination. The query used here is the one printed in
-- the manual (DECODE form); rows 2, 3 and 4 must be counted, rows 1 and 5 must not.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF
WHENEVER SQLERROR EXIT FAILURE

BEGIN
  EXECUTE IMMEDIATE 'DROP TABLE SFC_T_DECODE PURGE';
EXCEPTION
  WHEN OTHERS THEN NULL;
END;
/

CREATE TABLE SFC_T_DECODE (
  id      NUMBER PRIMARY KEY,
  label   VARCHAR2(40),
  rrn     VARCHAR2(20),
  rrn_enc VARCHAR2(136)
);

INSERT INTO SFC_T_DECODE VALUES (1, 'converted, same value',        '9001011234567', FN_SFC_ENC('9001011234567'));
INSERT INTO SFC_T_DECODE VALUES (2, 'not converted (enc is NULL)',  '9001011234568', NULL);
INSERT INTO SFC_T_DECODE VALUES (3, 'original removed, enc left',   NULL,            FN_SFC_ENC('9001011234569'));
INSERT INTO SFC_T_DECODE VALUES (4, 'values differ',                '9001011234570', FN_SFC_ENC('9001011234571'));
INSERT INTO SFC_T_DECODE VALUES (5, 'both NULL',                    NULL,            NULL);
COMMIT;

PROMPT --- per row (flagged = 1 means the check counts this row)
SELECT id, label, DECODE(FN_SFC_DEC(rrn_enc), rrn, 0, 1) AS flagged
  FROM SFC_T_DECODE
 ORDER BY id;

DECLARE
  v_ids VARCHAR2(100);
  v_new NUMBER;
  v_old NUMBER;
BEGIN
  SELECT COUNT(*) INTO v_new
    FROM SFC_T_DECODE
   WHERE DECODE(FN_SFC_DEC(rrn_enc), rrn, 0, 1) = 1;
  SELECT LISTAGG(id, ',') WITHIN GROUP (ORDER BY id) INTO v_ids
    FROM SFC_T_DECODE
   WHERE DECODE(FN_SFC_DEC(rrn_enc), rrn, 0, 1) = 1;
  -- the form that was printed in the manual before the review: it skips rows whose rrn is NULL
  SELECT COUNT(*) INTO v_old
    FROM SFC_T_DECODE
   WHERE rrn IS NOT NULL AND FN_SFC_DEC(rrn_enc) <> rrn;

  DBMS_OUTPUT.PUT_LINE('rows counted by the manual query : ' || v_new || ' (ids ' || v_ids || ')');
  DBMS_OUTPUT.PUT_LINE('rows counted by the old form     : ' || v_old || ' (for comparison only)');
  IF v_ids = '2,3,4' THEN
    DBMS_OUTPUT.PUT_LINE('PASS  T1 the query counts exactly the rows 2, 3 and 4');
  ELSE
    DBMS_OUTPUT.PUT_LINE('FAIL  T1 expected ids 2,3,4 but got ' || NVL(v_ids, '(none)'));
    RAISE_APPLICATION_ERROR(-20990, 'T1 failed. The table SFC_T_DECODE was left for inspection.');
  END IF;
END;
/

DROP TABLE SFC_T_DECODE PURGE;
PROMPT T1 done
