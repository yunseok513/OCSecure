-- OCS-LITE step 1 (run as SYS, in the target PDB)
--
-- Creates the single owner account and grants what the package needs.
-- All SQL files in lite/ are ASCII only on purpose: Korean text read through a
-- CP949 client can swallow line breaks and silently drop lines.
--
-- Usage:  @10_sys_setup.sql <owner_password> <tablespace>
--   example: @10_sys_setup.sql "Str0ng#Passw0rd" USERS

WHENEVER SQLERROR EXIT FAILURE
SET VERIFY OFF
SET SERVEROUTPUT ON

DEFINE owner_pwd = '&1'
DEFINE ts_name   = '&2'

CREATE USER SFC_OWNER IDENTIFIED BY "&owner_pwd"
  DEFAULT TABLESPACE &ts_name
  QUOTA 50M ON &ts_name;

GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE PROCEDURE TO SFC_OWNER;

-- DBMS_CRYPTO is not granted to PUBLIC. This grant is the only privilege the
-- module needs from SYS. If the site refuses it, the module cannot be installed.
GRANT EXECUTE ON SYS.DBMS_CRYPTO TO SFC_OWNER;

PROMPT
PROMPT SFC_OWNER created. Next: connect as SFC_OWNER and run 20_key_table.sql
