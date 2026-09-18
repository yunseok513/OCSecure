-- 오류 코드 정의
-- 오류 메시지에 평문, 키, 암호문 전체를 담지 않는다. 호출자에게는 일반화된
-- 메시지만 돌려주고 상세 사유는 감사 로그에만 남긴다.

CREATE OR REPLACE PACKAGE PKG_SEC_ERR AS
  e_bad_format     CONSTANT PLS_INTEGER := -20510;  -- 암호문 형식이 규격에 맞지 않음
  e_integrity      CONSTANT PLS_INTEGER := -20511;  -- 무결성 검증 실패(변조 또는 키 불일치)
  e_key_missing    CONSTANT PLS_INTEGER := -20512;  -- 키를 찾을 수 없거나 사용할 수 없는 상태
  e_keystore_shut  CONSTANT PLS_INTEGER := -20513;  -- 마스터 키가 반입되지 않음
  e_no_reveal      CONSTANT PLS_INTEGER := -20520;  -- 복호화 권한 없음
  e_no_app_ctx     CONSTANT PLS_INTEGER := -20521;  -- 애플리케이션 인증 문맥 없음
  e_rate_limit     CONSTANT PLS_INTEGER := -20522;  -- 복호화 사용량 임계치 초과
  e_no_domain      CONSTANT PLS_INTEGER := -20530;  -- 도메인 정의 없음
  e_bad_config     CONSTANT PLS_INTEGER := -20540;  -- 설정값 오류
  e_bad_arg        CONSTANT PLS_INTEGER := -20541;  -- 인자 오류

  PROCEDURE raise_err(p_code PLS_INTEGER, p_detail VARCHAR2 DEFAULT NULL);
END PKG_SEC_ERR;
/

CREATE OR REPLACE PACKAGE BODY PKG_SEC_ERR AS
  FUNCTION message_of(p_code PLS_INTEGER) RETURN VARCHAR2 IS
  BEGIN
    RETURN CASE p_code
             WHEN e_bad_format    THEN '암호문 형식 오류'
             WHEN e_integrity     THEN '무결성 검증 실패'
             WHEN e_key_missing   THEN '사용할 수 없는 키'
             WHEN e_keystore_shut THEN '키 저장소가 열려 있지 않음'
             WHEN e_no_reveal     THEN '복호화 권한 없음'
             WHEN e_no_app_ctx    THEN '애플리케이션 인증 문맥 없음'
             WHEN e_rate_limit    THEN '복호화 사용량 임계치 초과'
             WHEN e_no_domain     THEN '정의되지 않은 도메인'
             WHEN e_bad_config    THEN '설정값 오류'
             WHEN e_bad_arg       THEN '인자 오류'
             ELSE '암호 모듈 오류'
           END;
  END message_of;

  PROCEDURE raise_err(p_code PLS_INTEGER, p_detail VARCHAR2 DEFAULT NULL) IS
  BEGIN
    -- p_detail 은 운영자가 원인을 찾는 데 필요한 최소한만 담는다.
    -- 호출자에게 노출되므로 값 자체는 절대 포함하지 않는다.
    RAISE_APPLICATION_ERROR(
      p_code,
      'OCSecure: ' || message_of(p_code)
        || CASE WHEN p_detail IS NOT NULL THEN ' (' || SUBSTR(p_detail, 1, 200) || ')' END);
  END raise_err;
END PKG_SEC_ERR;
/
