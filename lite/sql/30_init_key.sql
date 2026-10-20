@@05_check_charset.sql
-- OCS-LITE 6단계 (SFC_OWNER 로 접속)
--
-- 첫 루트 키를 만듭니다. 한 번만 실행합니다. 끝나면 데이터베이스를 백업하십시오.
-- 키를 잃으면 그 키로 암호화한 자료는 누구도 복구할 수 없습니다.

SET SERVEROUTPUT ON

EXEC PKG_SFC.init_key

SELECT key_id, key_state, created_at FROM SFC_KEY ORDER BY key_id;
SELECT FN_SFC_READY AS ready FROM DUAL;
