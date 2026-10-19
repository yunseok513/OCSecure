-- OCS-LITE step 6 (run as LITE_OWNER)
--
-- Creates the first root key. Run it once. Back up the database afterwards:
-- data encrypted with a key that is lost cannot be recovered by anyone.

SET SERVEROUTPUT ON

EXEC PKG_LITE.init_key

SELECT key_id, key_state, created_at FROM LITE_KEY ORDER BY key_id;
SELECT LITE_READY AS ready FROM DUAL;
