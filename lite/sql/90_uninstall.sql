@@05_check_charset.sql
-- OCS-LITE 제거 (SYS 로 접속)
--
-- 경고: 키가 사라집니다. 그 키로 암호화된 자료는 다시는 읽을 수 없습니다.
-- 먼저 모든 암호문 컬럼을 평문으로 되돌리고(UPDATE t SET col = FN_SFC_DEC(col)),
-- 백업을 받고, 연결된 업무 스키마마다 41_disconnect_app.sql 을 실행한 뒤에 제거하십시오.

DROP USER SFC_OWNER CASCADE;
