-- OCSecure 설치 전 환경 점검
-- 설치 대상은 TO-BE 데이터베이스다. 데이터베이스를 바꾸지 않는 읽기 전용 점검이다.
--
-- 실행 계정은 SYS 를 권장한다. 다른 계정으로 돌리려면 그 계정에
-- SYS.DBMS_CRYPTO 에 대한 실행 권한이 있어야 한다. 이 패키지는 기본적으로
-- 아무에게도 공개되어 있지 않으므로, 권한이 없으면 제1항에서 그 사실을
-- 알려 주고 멈춘다.
--
-- DBMS_CRYPTO 호출을 동적 구문으로 감싼 이유가 있다. 그냥 부르면 권한이 없을 때
-- 블록 자체가 컴파일되지 않아 '식별자가 정의되어야 한다'는 오류만 나오고, 무엇이
-- 문제인지 알 수 없다. 동적 구문으로 두면 실행 시점에 확인되므로 원인을 짚어
-- 줄 수 있다.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF

DECLARE
  v_fail   PLS_INTEGER := 0;
  v_banner VARCHAR2(200);
  v_cs     VARCHAR2(60);
  v_dummy  RAW(64);
  v_cnt    PLS_INTEGER;

  PROCEDURE ok(p_msg VARCHAR2) IS
  BEGIN DBMS_OUTPUT.PUT_LINE('  [정상] ' || p_msg); END;

  PROCEDURE ng(p_msg VARCHAR2) IS
  BEGIN DBMS_OUTPUT.PUT_LINE('  [실패] ' || p_msg); v_fail := v_fail + 1; END;

  -- DBMS_CRYPTO 호출은 동적 구문으로 감싼다. 권한이 없어도 이 블록은 컴파일된다.
  FUNCTION try_crypto(p_body VARCHAR2) RETURN VARCHAR2 IS
    v RAW(64);
  BEGIN
    EXECUTE IMMEDIATE 'BEGIN :r := ' || p_body || '; END;' USING OUT v;
    RETURN NULL;
  EXCEPTION
    WHEN OTHERS THEN RETURN SQLERRM;
  END try_crypto;

  PROCEDURE check_crypto(p_name VARCHAR2, p_body VARCHAR2) IS
    v_err VARCHAR2(400) := try_crypto(p_body);
  BEGIN
    IF v_err IS NULL THEN
      ok(p_name || ' 사용 가능');
    ELSE
      ng(p_name || ' 사용 불가: ' || SUBSTR(v_err, 1, 120));
    END IF;
  END check_crypto;

BEGIN
  DBMS_OUTPUT.PUT_LINE('=== OCSecure 환경 점검 (대상: TO-BE 데이터베이스) ===');
  DBMS_OUTPUT.PUT_LINE('  실행 계정: ' || SYS_CONTEXT('USERENV', 'SESSION_USER'));
  DBMS_OUTPUT.PUT_LINE('  컨테이너: ' || SYS_CONTEXT('USERENV', 'CON_NAME'));

  -- 루트에 설치하면 안 된다. 여기서 먼저 잡는다.
  IF SYS_CONTEXT('USERENV', 'CON_NAME') = 'CDB$ROOT' THEN
    DBMS_OUTPUT.PUT_LINE('');
    ng('컨테이너 루트에 접속해 있다. 업무 PDB 가 아니다');
    DBMS_OUTPUT.PUT_LINE('    ALTER SESSION SET CONTAINER = <PDB이름>; 으로 들어간 뒤');
    DBMS_OUTPUT.PUT_LINE('    다시 실행할 것. PDB 목록은 000_where_am_i.sql 로 확인한다.');
    DBMS_OUTPUT.PUT_LINE('');
  END IF;

  SELECT banner INTO v_banner FROM v$version WHERE ROWNUM = 1;
  DBMS_OUTPUT.PUT_LINE('  버전: ' || v_banner);

  SELECT value INTO v_cs FROM nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET';
  DBMS_OUTPUT.PUT_LINE('  문자집합: ' || v_cs);
  DBMS_OUTPUT.PUT_LINE('  (구현은 UTL_I18N 으로 항상 UTF-8 로 인코딩하므로 문자집합에 의존하지 않는다)');
  DBMS_OUTPUT.PUT_LINE('');

  ---------------------------------------------- 1. DBMS_CRYPTO 접근 가능 여부
  BEGIN
    SELECT COUNT(*) INTO v_cnt
      FROM all_objects
     WHERE owner = 'SYS' AND object_name = 'DBMS_CRYPTO'
       AND object_type IN ('PACKAGE', 'SYNONYM');
  EXCEPTION
    WHEN OTHERS THEN v_cnt := 0;
  END;

  IF v_cnt = 0 THEN
    ng('SYS.DBMS_CRYPTO 를 볼 수 없다');
    DBMS_OUTPUT.PUT_LINE('');
    DBMS_OUTPUT.PUT_LINE('  원인은 둘 중 하나다.');
    DBMS_OUTPUT.PUT_LINE('    가. 실행 계정에 실행 권한이 없다. 이쪽이 대부분이다.');
    DBMS_OUTPUT.PUT_LINE('        이 패키지는 기본적으로 아무에게도 공개되어 있지 않다.');
    DBMS_OUTPUT.PUT_LINE('        SYS 로 접속하여 다음을 실행한 뒤 다시 점검한다.');
    DBMS_OUTPUT.PUT_LINE('          GRANT EXECUTE ON SYS.DBMS_CRYPTO TO ' ||
                         SYS_CONTEXT('USERENV', 'SESSION_USER') || ';');
    DBMS_OUTPUT.PUT_LINE('        또는 SYS 계정으로 이 스크립트를 다시 돌린다.');
    DBMS_OUTPUT.PUT_LINE('    나. 패키지 자체가 설치되어 있지 않다. 드물다.');
    DBMS_OUTPUT.PUT_LINE('        SYS 로 아래를 조회하여 확인한다.');
    DBMS_OUTPUT.PUT_LINE('          SELECT owner, object_name, status FROM dba_objects');
    DBMS_OUTPUT.PUT_LINE('           WHERE object_name = ''DBMS_CRYPTO'';');
  ELSE
    ok('SYS.DBMS_CRYPTO 접근 가능');

    -- 2. 필요한 알고리즘이 실제로 동작하는지
    check_crypto('DBMS_CRYPTO.HASH_SH256',
      'DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(''x''), DBMS_CRYPTO.HASH_SH256)');

    check_crypto('DBMS_CRYPTO.HMAC_SH256',
      'DBMS_CRYPTO.MAC(UTL_RAW.CAST_TO_RAW(''x''), DBMS_CRYPTO.HMAC_SH256, '
      || 'UTL_RAW.CAST_TO_RAW(''k''))');

    check_crypto('AES-256 / CBC / PKCS5',
      'DBMS_CRYPTO.ENCRYPT(UTL_RAW.CAST_TO_RAW(''0123456789ABCDEF''), '
      || 'DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5, '
      || 'HEXTORAW(RPAD(''AA'', 64, ''AA'')), HEXTORAW(RPAD(''BB'', 32, ''BB'')))');

    check_crypto('DBMS_CRYPTO.RANDOMBYTES', 'DBMS_CRYPTO.RANDOMBYTES(16)');
  END IF;

  ---------------------------------------------- 3. 문자집합 변환
  BEGIN
    -- 원본 파일의 한글 글자를 쓰면 접속 도구의 문자집합 설정에 따라 값이
    -- 달라져 엉뚱하게 실패할 수 있다. 유니코드 부호로 지정하여 그 영향을 없앤다.
    v_dummy := UTL_I18N.STRING_TO_RAW(UNISTR('\AC00'), 'AL32UTF8');
    IF v_dummy = HEXTORAW('EAB080') THEN
      ok('UTL_I18N UTF-8 인코딩 정상 (이 컨테이너 문자집합: ' || v_cs || ')');
    ELSE
      ng('UTL_I18N UTF-8 인코딩 결과가 예상과 다름: ' || RAWTOHEX(v_dummy));
    END IF;
  EXCEPTION
    WHEN OTHERS THEN
      ng('UTL_I18N 사용 불가: ' || SQLERRM);
  END;

  DBMS_OUTPUT.PUT_LINE('');
  DBMS_OUTPUT.PUT_LINE('=== 점검 종료: 실패 ' || v_fail || '건 ===');
  IF v_fail > 0 THEN
    DBMS_OUTPUT.PUT_LINE('실패 항목을 해소하기 전에는 설치하지 말 것.');
  END IF;
END;
/

SET FEEDBACK ON
