-- 스키마 전체의 암호화 의심 컬럼 조사
-- 기존 시스템 스키마를 읽을 수 있는 계정으로 실행한다.
--
-- 종합계획 제1단계 현황 분석에 쓰는 도구다. 어느 컬럼이 이미 암호화되어 있고
-- 어떤 형태인지를 한 번에 훑어, 이행 대상 목록의 초안을 만든다.
--
-- 판정은 생김새에 근거한 추정이다. 확정은 평문과 저장값 한 쌍을 확보하여
-- tools/legacy_pwd_probe.py 로 대조해야 한다.
--
-- 컬럼마다 표본을 읽으므로 큰 스키마에서는 시간이 걸린다. 업무 시간을 피해
-- 실행하는 편이 낫다. 저장값 자체는 출력하지 않는다.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET LINESIZE 200
SET FEEDBACK OFF

ACCEPT sch CHAR PROMPT '  조사할 스키마명: '

DECLARE
  c_sample CONSTANT PLS_INTEGER := 2000;   -- 컬럼당 표본 행 수
  c_min_n  CONSTANT PLS_INTEGER := 10;     -- 이보다 적으면 판단하지 않는다

  v_owner VARCHAR2(128) := UPPER('&sch');
  v_sql   VARCHAR2(4000);
  v_n     PLS_INTEGER;
  v_lens  PLS_INTEGER;
  v_min   PLS_INTEGER;
  v_max   PLS_INTEGER;
  v_b64   PLS_INTEGER;
  v_hex   PLS_INTEGER;
  v_dist  PLS_INTEGER;
  v_found PLS_INTEGER := 0;
  v_shape VARCHAR2(10);

  FUNCTION q(p_name IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN DBMS_ASSERT.ENQUOTE_NAME(p_name, FALSE);
  END q;

  FUNCTION guess(p_shape IN VARCHAR2, p_len IN PLS_INTEGER) RETURN VARCHAR2 IS
  BEGIN
    IF p_shape = 'BASE64' THEN
      RETURN CASE p_len
               WHEN 24 THEN '16바이트. MD5 또는 블록암호 1블록'
               WHEN 28 THEN '20바이트. SHA-1'
               WHEN 40 THEN '28바이트. SHA-224'
               WHEN 44 THEN '32바이트. SHA-256 또는 블록암호 2블록'
               WHEN 64 THEN '48바이트. SHA-384 또는 블록암호 3블록'
               WHEN 88 THEN '64바이트. SHA-512 또는 블록암호 4블록'
               ELSE '약 ' || TRUNC(p_len / 4 * 3) || '바이트'
             END;
    ELSIF p_shape = 'HEX' THEN
      RETURN CASE p_len
               WHEN 32  THEN '16바이트. MD5 또는 블록암호 1블록'
               WHEN 40  THEN '20바이트. SHA-1'
               WHEN 64  THEN '32바이트. SHA-256 또는 블록암호 2블록'
               WHEN 108 THEN '54바이트. OCSecure 비밀번호 형식'
               WHEN 128 THEN '64바이트. SHA-512'
               WHEN 136 THEN '68바이트. OCSecure 암호문(짧은 평문)'
               ELSE TO_CHAR(p_len / 2) || '바이트'
             END;
    END IF;
    RETURN '판단 보류';
  END guess;

BEGIN
  DBMS_OUTPUT.PUT_LINE('=== ' || v_owner || ' 스키마 암호화 의심 컬럼 ===');
  DBMS_OUTPUT.PUT_LINE('');
  DBMS_OUTPUT.PUT_LINE(RPAD('테이블.컬럼', 52) || RPAD('형태', 8)
                       || RPAD('길이', 6) || RPAD('중복', 7) || '추정');
  DBMS_OUTPUT.PUT_LINE(RPAD('-', 118, '-'));

  FOR c IN (SELECT t.table_name, t.column_name, t.data_type
              FROM all_tab_columns t
             WHERE t.owner = v_owner
               AND t.data_type IN ('VARCHAR2', 'CHAR', 'RAW')
               AND t.data_length BETWEEN 16 AND 1000
               AND EXISTS (SELECT 1 FROM all_tables a
                            WHERE a.owner = t.owner AND a.table_name = t.table_name)
             ORDER BY t.table_name, t.column_id)
  LOOP
    BEGIN
      v_sql := 'SELECT COUNT(*), COUNT(DISTINCT LENGTH(x)), MIN(LENGTH(x)), MAX(LENGTH(x)), '
            || 'SUM(CASE WHEN REGEXP_LIKE(x, ''^[A-Za-z0-9+/]+=*$'') THEN 1 ELSE 0 END), '
            || 'SUM(CASE WHEN REGEXP_LIKE(x, ''^[0-9a-fA-F]+$'') THEN 1 ELSE 0 END), '
            || 'COUNT(DISTINCT x) FROM (SELECT '
            || CASE WHEN c.data_type = 'RAW'
                    THEN 'RAWTOHEX(' || q(c.column_name) || ')'
                    ELSE q(c.column_name) END
            || ' AS x FROM ' || q(v_owner) || '.' || q(c.table_name)
            || ' WHERE ' || q(c.column_name) || ' IS NOT NULL'
            || ' FETCH FIRST ' || c_sample || ' ROWS ONLY)';

      EXECUTE IMMEDIATE v_sql
        INTO v_n, v_lens, v_min, v_max, v_b64, v_hex, v_dist;

      -- 판정 기준. 길이가 한 가지로 고르고, 표기 문자가 일관되며, 사람이 읽는
      -- 값이라고 보기에는 긴 컬럼만 추린다.
      IF v_n >= c_min_n AND v_lens = 1 AND v_min >= 24 THEN
        v_shape := CASE WHEN v_b64 = v_n AND v_hex < v_n THEN 'BASE64'
                        WHEN v_hex = v_n                 THEN 'HEX'
                        ELSE NULL END;

        IF v_shape IS NOT NULL THEN
          v_found := v_found + 1;
          DBMS_OUTPUT.PUT_LINE(
            RPAD(c.table_name || '.' || c.column_name, 52)
            || RPAD(v_shape, 8)
            || RPAD(TO_CHAR(v_min), 6)
            || RPAD(CASE WHEN v_dist < v_n THEN '있음' ELSE '없음' END, 7)
            || guess(v_shape, v_min));
        END IF;
      END IF;

    EXCEPTION
      WHEN OTHERS THEN
        -- 한 컬럼을 읽지 못해도 조사를 멈추지 않는다.
        NULL;
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE(RPAD('-', 118, '-'));
  DBMS_OUTPUT.PUT_LINE('의심 컬럼 ' || v_found || '개');
  DBMS_OUTPUT.PUT_LINE('');
  DBMS_OUTPUT.PUT_LINE('읽는 법');
  DBMS_OUTPUT.PUT_LINE('  중복 "있음"  서로 다른 행이 같은 값을 갖는다. 해시라면 솔트가 없다는');
  DBMS_OUTPUT.PUT_LINE('               뜻이고, 암호화라면 ECB 이거나 초기화 벡터가 고정이라는');
  DBMS_OUTPUT.PUT_LINE('               뜻이다. 어느 쪽이든 같은 값을 찾아낼 수 있다.');
  DBMS_OUTPUT.PUT_LINE('  중복 "없음"  사용자마다 다른 값이 섞여 들어갔거나, 원래 값이 모두');
  DBMS_OUTPUT.PUT_LINE('               제각각인 컬럼이다.');
  DBMS_OUTPUT.PUT_LINE('');
  DBMS_OUTPUT.PUT_LINE('다음 단계');
  DBMS_OUTPUT.PUT_LINE('  컬럼마다 평문을 아는 행을 한 건씩 확보하여 아래로 확정한다.');
  DBMS_OUTPUT.PUT_LINE('    python3 tools/legacy_pwd_probe.py --plain <평문> --stored <저장값>');
  DBMS_OUTPUT.PUT_LINE('  해시로 맞지 않고 원문 출력 업무가 있는 컬럼은 양방향 암호화이므로,');
  DBMS_OUTPUT.PUT_LINE('  기존 키를 찾아야 이행할 수 있다. 키 소재 파악을 별도 과제로 세운다.');
END;
/

SET FEEDBACK ON
