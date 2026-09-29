-- 기존 비밀번호 체계 (이행 기간 한정)
--
-- 조사로 확인된 기존 시스템의 저장 방식은 Base64(SHA-256(비밀번호))이며
-- 솔트도 아이디 결합도 없다. 근거는 셋이다. 저장값이 Base64 44자에 '=' 종료이므로
-- 32바이트이고, 32바이트를 내는 해시는 사실상 SHA-256 뿐이다. 그리고 서로 다른
-- 사용자 사이에 중복이 존재하므로 솔트와 아이디 결합이 함께 배제된다. 아이디를
-- 섞었다면 같은 비밀번호라도 사용자마다 값이 달라져 중복이 생기지 않는다.
--
-- 이는 추정이다. 배포 전에 실제 계정으로 self_check 를 통과시켜야 한다.
-- 통과하지 못하면 가정이 틀린 것이므로 조사부터 다시 해야 한다.
--
-- 이 패키지는 이행이 끝나면 삭제한다. 남겨 두면 약한 검증 경로가 계속 남는다.
-- 삭제 시점은 운영 절차에 명시할 것.
--
-- 주의: 이 방식은 약하다. 솔트가 없어 같은 비밀번호가 같은 값이 되고, 계산이
--       한 번뿐이라 유출되면 흔한 비밀번호는 즉시 복원된다. 그래서 이행 기간에도
--       옛 방식으로 로그인한 사용자에게는 비밀번호 변경을 강제한다.

CREATE OR REPLACE PACKAGE PKG_LEGACY_PWD AS

  c_legacy_len CONSTANT PLS_INTEGER := 44;

  -- 예전에 구축된 국내 시스템은 문자집합이 갈리는 경우가 있다. 한글이 섞인
  -- 비밀번호에서 결과가 달라지므로, 어느 것인지 확정해 두어야 한다.
  c_cs_utf8   CONSTANT VARCHAR2(30) := 'AL32UTF8';
  c_cs_win949 CONSTANT VARCHAR2(30) := 'KO16MSWIN949';
  c_cs_ksc    CONSTANT VARCHAR2(30) := 'KO16KSC5601';

  -- 소스에 상수로 박아 둔 고정 문자열을 섞는 구성이 드물지 않다. 그런 경우
  -- SEC_CONFIG 의 LEGACY_PWD_PREFIX 와 LEGACY_PWD_SUFFIX 에 넣으면 코드를
  -- 고치지 않고 대응할 수 있다. 확인은 self_check 로 한다.
  FUNCTION legacy_hash(p_password IN VARCHAR2,
                       p_charset  IN VARCHAR2 DEFAULT NULL,
                       p_prefix   IN VARCHAR2 DEFAULT NULL,
                       p_suffix   IN VARCHAR2 DEFAULT NULL) RETURN VARCHAR2;

  FUNCTION is_legacy(p_stored IN VARCHAR2) RETURN BOOLEAN;

  FUNCTION verify_legacy(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN BOOLEAN;

  -- 실제 계정의 평문과 저장값으로 가정이 맞는지 확인한다. 맞으면 어느 문자집합인지
  -- 돌려주고, 틀리면 '불일치'를 돌려준다. 배포 전에 반드시 통과시킬 것.
  FUNCTION self_check(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN VARCHAR2;

END PKG_LEGACY_PWD;
/

CREATE OR REPLACE PACKAGE BODY PKG_LEGACY_PWD AS

  FUNCTION cfg_charset RETURN VARCHAR2 IS
    v VARCHAR2(200);
  BEGIN
    SELECT cfg_value INTO v FROM SEC_CONFIG WHERE cfg_key = 'LEGACY_PWD_CHARSET';
    RETURN NVL(v, c_cs_utf8);
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN c_cs_utf8;
  END cfg_charset;

  FUNCTION cfg(p_key VARCHAR2) RETURN VARCHAR2 IS
    v VARCHAR2(200);
  BEGIN
    SELECT cfg_value INTO v FROM SEC_CONFIG WHERE cfg_key = p_key;
    RETURN v;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN NULL;
  END cfg;

  FUNCTION legacy_hash(p_password IN VARCHAR2,
                       p_charset  IN VARCHAR2 DEFAULT NULL,
                       p_prefix   IN VARCHAR2 DEFAULT NULL,
                       p_suffix   IN VARCHAR2 DEFAULT NULL) RETURN VARCHAR2 IS
    v_text VARCHAR2(4000);
  BEGIN
    IF p_password IS NULL THEN
      RETURN NULL;
    END IF;
    v_text := NVL(p_prefix, cfg('LEGACY_PWD_PREFIX'))
              || p_password
              || NVL(p_suffix, cfg('LEGACY_PWD_SUFFIX'));
    -- 32바이트를 Base64 로 바꾸면 44자이며 줄바꿈이 끼어들 길이가 아니다.
    RETURN UTL_RAW.CAST_TO_VARCHAR2(
             UTL_ENCODE.BASE64_ENCODE(
               PKG_PROVIDER_DBMS.digest(
                 UTL_I18N.STRING_TO_RAW(v_text, NVL(p_charset, cfg_charset)))));
  END legacy_hash;

  FUNCTION is_legacy(p_stored IN VARCHAR2) RETURN BOOLEAN IS
  BEGIN
    RETURN p_stored IS NOT NULL
       AND LENGTH(p_stored) = c_legacy_len
       AND REGEXP_LIKE(p_stored, '^[A-Za-z0-9+/]{43}=$');
  END is_legacy;

  FUNCTION verify_legacy(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN BOOLEAN IS
  BEGIN
    IF p_password IS NULL OR NOT is_legacy(p_stored) THEN
      RETURN FALSE;
    END IF;
    -- 길이가 같으므로 상수 시간 비교를 쓴다.
    RETURN PKG_CRYPTO_FMT.const_eq(
             UTL_I18N.STRING_TO_RAW(legacy_hash(p_password), 'AL32UTF8'),
             UTL_I18N.STRING_TO_RAW(p_stored, 'AL32UTF8'));
  END verify_legacy;

  FUNCTION self_check(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN VARCHAR2 IS
    TYPE t_cs IS TABLE OF VARCHAR2(30);
    v_list t_cs := t_cs(c_cs_utf8, c_cs_win949, c_cs_ksc);
  BEGIN
    IF p_password IS NULL OR p_stored IS NULL THEN
      RETURN '불일치 (인자가 비어 있음)';
    END IF;
    FOR i IN 1 .. v_list.COUNT LOOP
      BEGIN
        IF legacy_hash(p_password, v_list(i)) = p_stored THEN
          RETURN '일치 (문자집합 ' || v_list(i) || ')';
        END IF;
      EXCEPTION
        WHEN OTHERS THEN NULL;   -- 지원하지 않는 문자집합은 건너뛴다
      END;
    END LOOP;
    RETURN '불일치 (가정이 틀렸다. 조사부터 다시 할 것)';
  END self_check;

END PKG_LEGACY_PWD;
/
