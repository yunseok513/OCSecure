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

  -- 이행 기간용 -----------------------------------------------------------
  -- 기존 컬럼이 문자열이고 옛 형식과 새 형식이 섞여 있는 동안 쓴다.
  -- 새 형식은 16진 문자열 108자로, 옛 형식은 Base64 44자로 저장되므로 구분된다.
  -- 이행이 끝나면 이 두 함수와 PKG_LEGACY_PWD 를 함께 제거한다.

  FUNCTION make_pwd_str(p_password IN VARCHAR2) RETURN VARCHAR2;

  -- 0 = 불일치. 저장값이 비어 있는 경우도 여기에 포함된다.
  -- 1 = 일치, 현재 형식이다. 그대로 로그인시킨다.
  -- 2 = 일치, 옛 형식이다. 로그인시키되 비밀번호 변경을 강제한다.
  FUNCTION check_pwd(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN NUMBER;

  -- 저장값의 상태만 본다. 비밀번호를 입력받기 전에 화면을 고르는 데 쓴다.
  -- 업무포털 단일 인증으로 들어오는 이용자는 비밀번호를 쓰지 않으므로 저장값이
  -- 비어 있다. 그 상태를 로그인 실패와 구분해야 안내 문구를 제대로 낼 수 있다.
  --
  -- 0 = 미설정. 로그인시키지 말고 설정 절차로 보낸다.
  -- 1 = 현재 형식
  -- 2 = 옛 형식. 이행 기간에만 나타난다.
  -- 9 = 알 수 없는 형식. 통과시키지 않는다. 자료 이상이므로 조사가 필요하다.
  FUNCTION pwd_state(p_stored IN VARCHAR2) RETURN NUMBER;

  -- 운용 상태 ---------------------------------------------------------------
  -- 암복호화를 할 수 있는 상태인지 미리 물어본다. 1 이면 가능, 0 이면 불가다.
  --
  -- 키 저장소가 닫혀 있으면 모든 호출이 예외를 낸다. 그것이 안전한 동작이지만,
  -- 이용자에게 오류 추적이 그대로 보이는 것보다는 안내 화면을 내보내는 편이 낫다.
  -- 화면 진입 전에 이 값을 보고 갈라서 처리하라. 감시 도구의 상태 점검에도 쓴다.
  --
  -- 키 값이나 그 밖의 비밀은 드러나지 않는다. 열려 있는지 여부만 돌려준다.
  FUNCTION ready RETURN NUMBER;
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

  FUNCTION make_pwd_str(p_password IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN RAWTOHEX(PKG_CRYPTO_CORE.pwd_hash(p_password));
  END make_pwd_str;

  FUNCTION check_pwd(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN NUMBER IS
    c_hex_len CONSTANT PLS_INTEGER := PKG_CRYPTO_CORE.c_pwd_blob_len * 2;   -- 108
  BEGIN
    IF p_password IS NULL OR p_stored IS NULL THEN
      RETURN 0;
    END IF;

    -- 현재 형식인가. 16진 문자열이므로 길이와 문자 구성으로 판별한다.
    IF LENGTH(p_stored) = c_hex_len
       AND REGEXP_LIKE(p_stored, '^[0-9A-Fa-f]+$') THEN
      RETURN CASE WHEN PKG_CRYPTO_CORE.pwd_verify(p_password, HEXTORAW(p_stored))
                  THEN 1 ELSE 0 END;
    END IF;

    -- 옛 형식인가. 맞으면 로그인은 시키되 변경을 요구하라는 뜻으로 2 를 돌려준다.
    IF PKG_LEGACY_PWD.is_legacy(p_stored) THEN
      RETURN CASE WHEN PKG_LEGACY_PWD.verify_legacy(p_password, p_stored)
                  THEN 2 ELSE 0 END;
    END IF;

    -- 어느 쪽도 아니면 조사에서 놓친 형식이다. 통과시키지 않는다.
    RETURN 0;
  END check_pwd;

  FUNCTION ready RETURN NUMBER IS
  BEGIN
    RETURN CASE WHEN PKG_KEK_PROVIDER.is_open THEN 1 ELSE 0 END;
  EXCEPTION
    WHEN OTHERS THEN
      -- 상태를 묻는 호출이 예외로 끝나면 안내를 낼 수 없다. 모르면 불가로 본다.
      RETURN 0;
  END ready;

  FUNCTION pwd_state(p_stored IN VARCHAR2) RETURN NUMBER IS
    c_hex_len CONSTANT PLS_INTEGER := PKG_CRYPTO_CORE.c_pwd_blob_len * 2;   -- 108
  BEGIN
    -- 오라클에서 빈 문자열은 널이므로 둘을 따로 볼 필요가 없다.
    IF p_stored IS NULL THEN
      RETURN 0;
    END IF;
    IF LENGTH(p_stored) = c_hex_len
       AND REGEXP_LIKE(p_stored, '^[0-9A-Fa-f]+$') THEN
      RETURN 1;
    END IF;
    IF PKG_LEGACY_PWD.is_legacy(p_stored) THEN
      RETURN 2;
    END IF;
    RETURN 9;
  END pwd_state;

END PKG_SECURE_API;
/
