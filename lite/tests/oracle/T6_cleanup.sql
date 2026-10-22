-- OCS-LITE acceptance check T6: remove the test table
--
-- Run as SFC_OWNER when all checks are done. Only the table SFC_T_PERSIST is removed.
-- Keys created by a rotation in T4 stay in SFC_KEY: they cannot and must not be removed.

SET FEEDBACK OFF
WHENEVER SQLERROR EXIT FAILURE
DROP TABLE SFC_T_PERSIST PURGE;
PROMPT T6 done
