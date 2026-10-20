@@05_check_charset.sql
-- OCS-LITE 1단계 (SYS 로 접속, 대상 PDB 에서 실행)
--
-- 소유 계정을 만들고 패키지에 필요한 권한을 줍니다.
--
-- 사용법:  @10_sys_setup.sql <소유 계정 암호> <테이블스페이스>
--   예)    @10_sys_setup.sql "Str0ng#Passw0rd" USERS

WHENEVER SQLERROR EXIT FAILURE
SET VERIFY OFF
SET SERVEROUTPUT ON

DEFINE owner_pwd = '&1'
DEFINE ts_name   = '&2'

CREATE USER SFC_OWNER IDENTIFIED BY "&owner_pwd"
  DEFAULT TABLESPACE &ts_name
  QUOTA 50M ON &ts_name;

GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE PROCEDURE TO SFC_OWNER;

-- DBMS_CRYPTO 는 PUBLIC 에 열려 있지 않습니다. 이 권한이 SYS 에서 받아야 하는
-- 유일한 권한이며, 현장에서 이 권한을 거부하면 모듈을 설치할 수 없습니다.
GRANT EXECUTE ON SYS.DBMS_CRYPTO TO SFC_OWNER;

PROMPT
PROMPT SFC_OWNER created. Next: connect as SFC_OWNER and run 20_key_table.sql
