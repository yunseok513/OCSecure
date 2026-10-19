-- OCS-LITE uninstall (run as SYS)
--
-- WARNING: this destroys the keys. Anything still encrypted with them can never
-- be read again. Decrypt the data first (UPDATE t SET col = FN_SFC_DEC(col)), take a
-- backup, and run 41_disconnect_app.sql for every connected schema.

DROP USER SFC_OWNER CASCADE;
