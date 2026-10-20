@@05_check_charset.sql
-- OCS-LITE 3단계 (SFC_OWNER 로 접속)
--
-- SFC_KEY 에 저장되는 루트 키를 감싸는 32바이트 난수(봉인값)를 담은 SFC_SEAL 패키지를
-- 만듭니다. 봉인값은 여기서 한 번만 만들어지며 PKG_SFC 를 다시 컴파일해도 바뀌지
-- 않습니다. 봉인값을 잃거나 바꾸면 저장된 키를 모두 읽을 수 없게 되므로, 이 스크립트는
-- 두 번째 실행을 스스로 거부합니다.
--
-- 선택 사항: 만들어진 패키지 소스를 오라클 wrap 도구로 감싸 두면 DBA_SOURCE 에서 값이
-- 바로 보이지 않습니다. 값을 감출 뿐이며, 데이터베이스 전체를 가진 사람은 막지 못합니다.
-- 안내서를 참조하십시오.

SET SERVEROUTPUT ON

-- SFC_SEAL: 모듈 내부용입니다. 직접 호출하지 말고, 누구에게도 권한을 주지 말고, 지우지 마십시오.
-- 지우거나 다시 만들면 저장된 키를 모두 읽을 수 없게 됩니다.
CREATE OR REPLACE PACKAGE SFC_SEAL AS
  FUNCTION get_seal RETURN RAW;
END SFC_SEAL;
/

DECLARE
  v_exists NUMBER;
  v_hex    VARCHAR2(64);
BEGIN
  SELECT COUNT(*) INTO v_exists
    FROM user_objects
   WHERE object_name = 'SFC_SEAL' AND object_type = 'PACKAGE BODY';
  IF v_exists > 0 THEN
    DBMS_OUTPUT.PUT_LINE('SFC_SEAL body already exists. Left unchanged on purpose.');
    RETURN;
  END IF;
  v_hex := RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(32));
  EXECUTE IMMEDIATE
    'CREATE OR REPLACE PACKAGE BODY SFC_SEAL AS '
    || 'FUNCTION get_seal RETURN RAW IS BEGIN RETURN HEXTORAW(''' || v_hex
    || '''); END get_seal; END SFC_SEAL;';
  DBMS_OUTPUT.PUT_LINE('SFC_SEAL created.');
END;
/

SELECT object_name, object_type, status FROM user_objects WHERE object_name = 'SFC_SEAL';
