-- OCS-LITE acceptance check T3: leave ciphertext behind for the restart, rotation and restore checks
--
-- TEST INSTANCE ONLY. Run as SFC_OWNER. Creates table SFC_T_PERSIST and stores two values
-- encrypted with the CURRENT key. T4, T5 and T6 use this table. Run T3 once.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF
WHENEVER SQLERROR EXIT FAILURE

CREATE TABLE SFC_T_PERSIST (
  id    NUMBER PRIMARY KEY,
  phase VARCHAR2(20),
  plain VARCHAR2(40),
  enc   VARCHAR2(400)
);

INSERT INTO SFC_T_PERSIST VALUES (1, 'before-rotation', '9001011234567',
                                  PKG_SFC.encrypt_hex('9001011234567'));
INSERT INTO SFC_T_PERSIST VALUES (2, 'before-rotation', TO_CHAR(UNISTR('\D55C\AE00')),
                                  PKG_SFC.encrypt_hex(TO_CHAR(UNISTR('\D55C\AE00'))));
COMMIT;

PROMPT --- stored rows and the key number inside each ciphertext (characters 5 to 8)
SELECT id, phase, SUBSTR(enc, 5, 4) AS key_hex, LENGTH(enc) AS len FROM SFC_T_PERSIST ORDER BY id;
PROMPT --- keys
SELECT key_id, key_state FROM SFC_KEY ORDER BY key_id;
PROMPT T3 done
