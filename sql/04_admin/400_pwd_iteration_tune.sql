-- 비밀번호 반복 횟수 측정과 조정
-- OCS_OWNER 계정으로 실행한다. PKG_CRYPTO_CORE 는 어떤 계정에도 실행 권한이
-- 부여되어 있지 않으므로 다른 계정으로는 측정할 수 없다.
--
-- 반복 횟수는 비밀번호 저장값의 세기를 결정한다. 높을수록 유출 시 대량 대입이
-- 어려워지지만 로그인 응답 시간도 그만큼 늘어난다. 정답이 없고 장비 성능에
-- 전적으로 의존하므로, 측정한 뒤 응답 시간이 허용하는 범위에서 최대한 올린다.
--
-- 측정에 쓰는 문자열은 아무 값이나 상관없다. 반복 횟수만이 소요 시간을 좌우한다.
--
-- 이 스크립트는 아무것도 묻지 않고 아무것도 바꾸지 않는다. 재고 보여 줄 뿐이다.
-- 변경 구문은 끝에 안내로만 나오므로 직접 실행해야 적용된다.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF

PROMPT
PROMPT === 1. 현재 설정 ===
SELECT cfg_key, cfg_value, description FROM SEC_CONFIG WHERE cfg_key = 'PWD_ITERATIONS';

PROMPT
PROMPT === 2. 반복 횟수별 소요 시간 측정 ===
DECLARE
  TYPE t_iters IS TABLE OF PLS_INTEGER;
  v_iters t_iters := t_iters(5000, 10000, 20000, 50000, 100000, 200000);

  c_rounds  CONSTANT PLS_INTEGER := 5;   -- 평균을 내기 위한 반복 측정 횟수
  c_salt    CONSTANT RAW(16) := HEXTORAW('000102030405060708090A0B0C0D0E0F');
  c_sample  CONSTANT VARCHAR2(40) := 'MeasureOnly!2026';

  v_t0 PLS_INTEGER;
  v_ms NUMBER;
  v    RAW(64);
BEGIN
  DBMS_OUTPUT.PUT_LINE('  반복 횟수        1회 소요(밀리초)   초당 처리 가능 횟수');
  DBMS_OUTPUT.PUT_LINE('  ---------------  -----------------  -------------------');

  FOR i IN 1 .. v_iters.COUNT LOOP
    v_t0 := DBMS_UTILITY.GET_TIME;          -- 1/100초 단위
    FOR r IN 1 .. c_rounds LOOP
      v := PKG_CRYPTO_CORE.pwd_hash(c_sample, c_salt, v_iters(i));
    END LOOP;
    v_ms := (DBMS_UTILITY.GET_TIME - v_t0) * 10 / c_rounds;

    DBMS_OUTPUT.PUT_LINE('  ' || LPAD(TO_CHAR(v_iters(i), 'FM999,999,999'), 15)
                         || LPAD(TO_CHAR(v_ms, 'FM999,990.0'), 19)
                         || LPAD(CASE WHEN v_ms > 0
                                      THEN TO_CHAR(1000 / v_ms, 'FM999,990.0')
                                      ELSE '측정 불가' END, 21));
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('');
  DBMS_OUTPUT.PUT_LINE('  판단 기준: 로그인 한 건에 허용할 수 있는 시간을 먼저 정하고');
  DBMS_OUTPUT.PUT_LINE('             그 안에 드는 가장 큰 반복 횟수를 고른다.');
  DBMS_OUTPUT.PUT_LINE('             동시 로그인이 몰리는 시각의 부하도 함께 고려할 것.');
  DBMS_OUTPUT.PUT_LINE('             측정값은 이 장비의 현재 부하 상태에 따라 달라지므로');
  DBMS_OUTPUT.PUT_LINE('             한산한 시각과 붐비는 시각에 각각 재어 보는 편이 낫다.');
END;
/

PROMPT
PROMPT === 3. 반복 횟수 변경 ===
PROMPT     아래 구문의 숫자를 측정 결과에 맞추어 고쳐 실행한다.
PROMPT     변경은 즉시 반영되며, 이후 새로 저장되는 값부터 적용된다.
PROMPT     기존 저장값은 그대로 두어도 검증에 문제가 없다.
PROMPT
PROMPT       UPDATE SEC_CONFIG SET cfg_value = '50000', updated_at = SYSTIMESTAMP
PROMPT        WHERE cfg_key = 'PWD_ITERATIONS';
PROMPT       COMMIT;
PROMPT
PROMPT     내린 적은 없어야 한다. 낮추면 이미 저장된 값보다 약한 값이 새로 생긴다.
PROMPT
PROMPT     이미 운영 중이어서 저장값이 쌓여 있다면, 401_pwd_iteration_dist.sql 로
PROMPT     기존 저장값들이 어떤 반복 횟수로 만들어졌는지 살펴볼 수 있다.
PROMPT     개통 전에는 저장값이 없으므로 그 스크립트는 쓸 일이 없다.

SET FEEDBACK ON
