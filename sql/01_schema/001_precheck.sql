-- OCSecure 설치 전 환경 점검
-- 설치 대상 인스턴스가 이 구현이 요구하는 기능을 제공하는지 확인한다.
-- SYS 또는 그에 준하는 권한으로 실행한다.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF

DECLARE
  v_fail   PLS_INTEGER := 0;
  v_banner VARCHAR2(200);
  v_cs     VARCHAR2(60);
  v_dummy  RAW(64);

  PROCEDURE ok(p_msg VARCHAR2) IS
  BEGIN DBMS_OUTPUT.PUT_LINE('  [정상] ' || p_msg); END;

  PROCEDURE ng(p_msg VARCHAR2) IS
  BEGIN DBMS_OUTPUT.PUT_LINE('  [실패] ' || p_msg); v_fail := v_fail + 1; END;
BEGIN
  DBMS_OUTPUT.PUT_LINE('=== OCSecure 환경 점검 ===');

  SELECT banner INTO v_banner FROM v$version WHERE ROWNUM = 1;
  DBMS_OUTPUT.PUT_LINE('  버전: ' || v_banner);

  SELECT value INTO v_cs FROM nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET';
  DBMS_OUTPUT.PUT_LINE('  문자집합: ' || v_cs);
  DBMS_OUTPUT.PUT_LINE('  (구현은 UTL_I18N 으로 항상 UTF-8 로 인코딩하므로 문자집합에 의존하지 않는다)');

  -- SHA-256 계열 가용 여부. 12c 이전이면 이 구현은 설치할 수 없다.
  BEGIN
    v_dummy := DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW('x'), DBMS_CRYPTO.HASH_SH256);
    ok('DBMS_CRYPTO.HASH_SH256 사용 가능');
  EXCEPTION WHEN OTHERS THEN
    ng('DBMS_CRYPTO.HASH_SH256 사용 불가: ' || SQLERRM);
  END;

  BEGIN
    v_dummy := DBMS_CRYPTO.MAC(UTL_RAW.CAST_TO_RAW('x'), DBMS_CRYPTO.HMAC_SH256,
                               UTL_RAW.CAST_TO_RAW('k'));
    ok('DBMS_CRYPTO.HMAC_SH256 사용 가능');
  EXCEPTION WHEN OTHERS THEN
    ng('DBMS_CRYPTO.HMAC_SH256 사용 불가: ' || SQLERRM);
  END;

  BEGIN
    v_dummy := DBMS_CRYPTO.ENCRYPT(
                 src => UTL_RAW.CAST_TO_RAW('0123456789ABCDEF'),
                 typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC
                        + DBMS_CRYPTO.PAD_PKCS5,
                 key => HEXTORAW(RPAD('AA', 64, 'AA')),
                 iv  => HEXTORAW(RPAD('BB', 32, 'BB')));
    ok('AES-256 / CBC / PKCS5 사용 가능');
  EXCEPTION WHEN OTHERS THEN
    ng('AES-256 CBC 사용 불가: ' || SQLERRM);
  END;

  BEGIN
    v_dummy := DBMS_CRYPTO.RANDOMBYTES(16);
    ok('DBMS_CRYPTO.RANDOMBYTES 사용 가능');
  EXCEPTION WHEN OTHERS THEN
    ng('DBMS_CRYPTO.RANDOMBYTES 사용 불가: ' || SQLERRM);
  END;

  BEGIN
    v_dummy := UTL_I18N.STRING_TO_RAW('가', 'AL32UTF8');
    IF v_dummy = HEXTORAW('EAB080') THEN
      ok('UTL_I18N UTF-8 인코딩 정상');
    ELSE
      ng('UTL_I18N UTF-8 인코딩 결과가 예상과 다름: ' || RAWTOHEX(v_dummy));
    END IF;
  EXCEPTION WHEN OTHERS THEN
    ng('UTL_I18N 사용 불가: ' || SQLERRM);
  END;

  DBMS_OUTPUT.PUT_LINE('=== 점검 종료: 실패 ' || v_fail || '건 ===');
  IF v_fail > 0 THEN
    RAISE_APPLICATION_ERROR(-20999,
      '환경 점검에 실패하였다. 실패 항목을 해소하기 전에는 설치하지 말 것.');
  END IF;
END;
/

SET FEEDBACK ON
