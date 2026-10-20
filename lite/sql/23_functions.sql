@@05_check_charset.sql
-- OCS-LITE 5단계 (SFC_OWNER 로 접속)
--
-- 응용이 호출하는 함수입니다. 업무 스키마에는 이 여섯 함수의 실행 권한만 줍니다
-- (40_connect_app.sql). 연결하면 접두어 없이 쓸 수 있습니다.
--
--   INSERT INTO member (rrn_enc, pw_hash)
--   VALUES (FN_SFC_ENC('9001011234567'), FN_SFC_PWD_HASH('사용자가 입력한 비밀번호'));
--
--   SELECT FN_SFC_DEC(rrn_enc), FN_SFC_MASK(rrn_enc, 'RRN') FROM member;
--   SELECT FN_SFC_PWD_VERIFY('사용자가 입력한 비밀번호', pw_hash) FROM member;
--
-- 오류는 ORA-206xx 로 발생합니다. 안내서 제7장을 참조하십시오.

-- FN_SFC_ENC: 식별번호(주민등록번호, 계좌번호)를 암호화합니다.
--   p_plain  평문. NULL 이면 NULL 을 돌려줍니다. UTF-8 로 1900바이트 이하.
-- 반환       VARCHAR2 컬럼에 저장할 16진 문자열 (13글자 입력이면 136자).
--            호출마다 값이 달라 WHERE 조건에는 쓸 수 없습니다.
-- 오류       -20601 평문이 너무 김, -20602 사용할 수 있는 키가 없음.
CREATE OR REPLACE FUNCTION FN_SFC_ENC(p_plain IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.encrypt_hex(p_plain);
END FN_SFC_ENC;
/

-- FN_SFC_DEC: FN_SFC_ENC 로 만든 값에서 원래 문자열을 되돌립니다.
--   p_hex    저장된 값. NULL 이면 NULL 을 돌려줍니다.
-- 반환       원래 문자열. 로그, 임시 테이블, 공개된 뷰에 남기지 마십시오.
-- 오류       -20604 이 모듈의 값이 아님 (컬럼 길이를 확인), -20603 변조된 값,
--            -20602 키를 찾을 수 없음.
CREATE OR REPLACE FUNCTION FN_SFC_DEC(p_hex IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.decrypt_hex(p_hex);
END FN_SFC_DEC;
/

-- FN_SFC_MASK: 저장된 값의 일부를 가려서 보여 줍니다. 전체 평문은 드러나지 않습니다.
--   p_hex    저장된 값. NULL 이면 NULL 을 돌려줍니다.
--   p_type   RRN      900101-*******  (숫자 13자리. 자리수가 다르면 ********)
--            ACCOUNT  앞 4글자만 보이고 나머지는 *
--            ALL      ********       (기본값)
-- 오류       -20601 알 수 없는 p_type, 그리고 FN_SFC_DEC 의 오류.
CREATE OR REPLACE FUNCTION FN_SFC_MASK(p_hex IN VARCHAR2, p_type IN VARCHAR2 DEFAULT 'ALL') RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.mask_hex(p_hex, p_type);
END FN_SFC_MASK;
/

-- FN_SFC_PWD_HASH: 비밀번호로 저장할 값을 만듭니다. 되돌릴 수 없습니다.
--   p_password  비밀번호. NULL 이나 빈 문자열은 거부합니다.
-- 반환          108자 16진 문자열. 같은 비밀번호도 호출마다 값이 다릅니다.
-- 오류          -20601 빈 비밀번호.
-- 참고          일부러 시간이 걸리게 만든 계산입니다. 설치 후 소요 시간을 재어 보십시오 (안내서 4.2절).
CREATE OR REPLACE FUNCTION FN_SFC_PWD_HASH(p_password IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SFC.pwd_hash_hex(p_password);
END FN_SFC_PWD_HASH;
/

-- FN_SFC_PWD_VERIFY: FN_SFC_PWD_HASH 로 저장한 값과 비밀번호가 맞는지 확인합니다.
--   p_password  사용자가 입력한 비밀번호.
--   p_stored    저장된 값.
-- 반환          맞으면 1, 아니면 0. 입력이 NULL 이거나 깨져 있어도 오류가 아니라 0 입니다.
CREATE OR REPLACE FUNCTION FN_SFC_PWD_VERIFY(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN NUMBER IS
BEGIN
  RETURN PKG_SFC.pwd_verify_hex(p_password, p_stored);
END FN_SFC_PWD_VERIFY;
/

-- FN_SFC_READY: 지금 암호화를 쓸 수 있으면 1, 아니면 0. 오류를 던지지 않습니다.
--               감시에 쓰십시오: SELECT FN_SFC_READY FROM DUAL;
CREATE OR REPLACE FUNCTION FN_SFC_READY RETURN NUMBER IS
BEGIN
  RETURN PKG_SFC.is_ready;
END FN_SFC_READY;
/

SELECT object_name, status FROM user_objects
 WHERE object_name LIKE 'FN\_SFC\_%' ESCAPE '\' AND object_type = 'FUNCTION'
 ORDER BY object_name;
