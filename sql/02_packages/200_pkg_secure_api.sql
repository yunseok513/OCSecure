-- 인터페이스 계층
--
-- 애플리케이션과 배치가 실제로 호출하는 유일한 진입점이다. 응용 계정에는 이
-- 패키지에만 실행 권한을 부여하고, 그 아래 계층에는 어떤 권한도 주지 않는다.
--
-- 함수 이름을 업무 의미로 지은 이유는 호출 지점을 찾기 쉽게 하기 위해서다.
-- 나중에 어떤 화면이 주민등록번호를 평문으로 쓰는지 조사할 때, 이름으로 검색하면
-- 바로 드러난다.

CREATE OR REPLACE PACKAGE PKG_SECURE_API AS

  -- 표준 도메인 코드. 신규 도메인은 PKG_KEY_ADMIN.upsert_domain 으로 추가한다.
  c_rrn     CONSTANT VARCHAR2(30) := 'RRN';       -- 주민등록번호
  c_account CONSTANT VARCHAR2(30) := 'ACCOUNT';   -- 계좌번호
  c_name    CONSTANT VARCHAR2(30) := 'NAME';      -- 성명
  c_phone   CONSTANT VARCHAR2(30) := 'PHONE';     -- 연락처
  c_email   CONSTANT VARCHAR2(30) := 'EMAIL';     -- 전자우편 주소
  c_addr    CONSTANT VARCHAR2(30) := 'ADDR';      -- 주소

  -- 세션 확립 -----------------------------------------------------------
  PROCEDURE login (p_app_user IN VARCHAR2,
                   p_epoch    IN NUMBER DEFAULT NULL,
                   p_proof    IN RAW    DEFAULT NULL);
  PROCEDURE logout;

  -- 일반형 --------------------------------------------------------------
  FUNCTION protect  (p_domain_code IN VARCHAR2, p_plain  IN VARCHAR2) RETURN RAW;
  FUNCTION reveal   (p_domain_code IN VARCHAR2, p_cipher IN RAW)      RETURN VARCHAR2;
  FUNCTION masked   (p_domain_code IN VARCHAR2, p_cipher IN RAW)      RETURN VARCHAR2;
  FUNCTION show     (p_domain_code IN VARCHAR2, p_cipher IN RAW)      RETURN VARCHAR2;
  FUNCTION search_of(p_domain_code IN VARCHAR2, p_plain  IN VARCHAR2) RETURN RAW;
  FUNCTION allowed  (p_domain_code IN VARCHAR2)                       RETURN VARCHAR2;

  -- 주민등록번호 ---------------------------------------------------------
  FUNCTION enc_rrn   (p_rrn    IN VARCHAR2) RETURN RAW;
  FUNCTION dec_rrn   (p_cipher IN RAW)      RETURN VARCHAR2;
  FUNCTION mask_rrn  (p_cipher IN RAW)      RETURN VARCHAR2;
  FUNCTION idx_rrn   (p_rrn    IN VARCHAR2) RETURN RAW;

  -- 계좌번호 -------------------------------------------------------------
  FUNCTION enc_account (p_account IN VARCHAR2) RETURN RAW;
  FUNCTION dec_account (p_cipher  IN RAW)      RETURN VARCHAR2;
  FUNCTION mask_account(p_cipher  IN RAW)      RETURN VARCHAR2;
  FUNCTION idx_account (p_account IN VARCHAR2) RETURN RAW;

  -- 성명 -----------------------------------------------------------------
  FUNCTION enc_name  (p_name   IN VARCHAR2) RETURN RAW;
  FUNCTION dec_name  (p_cipher IN RAW)      RETURN VARCHAR2;
  FUNCTION mask_name (p_cipher IN RAW)      RETURN VARCHAR2;
  FUNCTION idx_name  (p_name   IN VARCHAR2) RETURN RAW;

  -- 비밀번호(일방향) -------------------------------------------------------
  FUNCTION make_pwd  (p_password IN VARCHAR2) RETURN RAW;
  FUNCTION verify_pwd(p_password IN VARCHAR2, p_stored IN RAW) RETURN NUMBER;  -- 1 또는 0
  FUNCTION pwd_stale (p_stored   IN RAW) RETURN NUMBER;                        -- 1 또는 0
END PKG_SECURE_API;
/

CREATE OR REPLACE PACKAGE BODY PKG_SECURE_API AS

  PROCEDURE login(p_app_user IN VARCHAR2,
                  p_epoch    IN NUMBER DEFAULT NULL,
                  p_proof    IN RAW    DEFAULT NULL) IS
  BEGIN
    PKG_APP_CONTEXT.set_identity(p_app_user, p_epoch, p_proof);
  END login;

  PROCEDURE logout IS
  BEGIN
    PKG_APP_CONTEXT.clear_identity;
  END logout;

  FUNCTION protect(p_domain_code IN VARCHAR2, p_plain IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN PKG_CRYPTO_POLICY.protect(p_domain_code, p_plain);
  END protect;

  FUNCTION reveal(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN
    RETURN PKG_CRYPTO_POLICY.reveal(p_domain_code, p_cipher);
  END reveal;

  FUNCTION masked(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN
    RETURN PKG_CRYPTO_POLICY.mask(p_domain_code, p_cipher);
  END masked;

  FUNCTION show(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN
    -- 목록 화면의 기본 선택지. 자격이 있으면 평문을, 없으면 마스킹을 돌려준다.
    RETURN PKG_CRYPTO_POLICY.reveal_or_mask(p_domain_code, p_cipher);
  END show;

  FUNCTION search_of(p_domain_code IN VARCHAR2, p_plain IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN PKG_CRYPTO_POLICY.index_of(p_domain_code, p_plain);
  END search_of;

  FUNCTION allowed(p_domain_code IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN PKG_CRYPTO_POLICY.can_reveal(p_domain_code);
  END allowed;

  FUNCTION enc_rrn(p_rrn IN VARCHAR2) RETURN RAW IS
  BEGIN RETURN protect(c_rrn, p_rrn); END enc_rrn;

  FUNCTION dec_rrn(p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN RETURN reveal(c_rrn, p_cipher); END dec_rrn;

  FUNCTION mask_rrn(p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN RETURN masked(c_rrn, p_cipher); END mask_rrn;

  FUNCTION idx_rrn(p_rrn IN VARCHAR2) RETURN RAW IS
  BEGIN RETURN search_of(c_rrn, p_rrn); END idx_rrn;

  FUNCTION enc_account(p_account IN VARCHAR2) RETURN RAW IS
  BEGIN RETURN protect(c_account, p_account); END enc_account;

  FUNCTION dec_account(p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN RETURN reveal(c_account, p_cipher); END dec_account;

  FUNCTION mask_account(p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN RETURN masked(c_account, p_cipher); END mask_account;

  FUNCTION idx_account(p_account IN VARCHAR2) RETURN RAW IS
  BEGIN RETURN search_of(c_account, p_account); END idx_account;

  FUNCTION enc_name(p_name IN VARCHAR2) RETURN RAW IS
  BEGIN RETURN protect(c_name, p_name); END enc_name;

  FUNCTION dec_name(p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN RETURN reveal(c_name, p_cipher); END dec_name;

  FUNCTION mask_name(p_cipher IN RAW) RETURN VARCHAR2 IS
  BEGIN RETURN masked(c_name, p_cipher); END mask_name;

  FUNCTION idx_name(p_name IN VARCHAR2) RETURN RAW IS
  BEGIN RETURN search_of(c_name, p_name); END idx_name;

  FUNCTION make_pwd(p_password IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN PKG_CRYPTO_CORE.pwd_hash(p_password);
  END make_pwd;

  FUNCTION verify_pwd(p_password IN VARCHAR2, p_stored IN RAW) RETURN NUMBER IS
  BEGIN
    -- SQL 에서 직접 부를 수 있도록 불리언 대신 숫자를 돌려준다.
    RETURN CASE WHEN PKG_CRYPTO_CORE.pwd_verify(p_password, p_stored) THEN 1 ELSE 0 END;
  END verify_pwd;

  FUNCTION pwd_stale(p_stored IN RAW) RETURN NUMBER IS
  BEGIN
    -- 1 이면 로그인 성공 시점에 현재 기준으로 다시 계산하여 저장할 것.
    RETURN CASE WHEN PKG_CRYPTO_CORE.pwd_needs_upgrade(p_stored) THEN 1 ELSE 0 END;
  END pwd_stale;

END PKG_SECURE_API;
/
