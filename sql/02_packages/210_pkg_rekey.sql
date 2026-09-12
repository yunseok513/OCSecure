-- 재암호화 배치
--
-- 키 교체와 알고리즘 교체에 공통으로 쓴다. 검증필 암호모듈로 전환할 때도 같은
-- 도구를 쓰므로, 이 배치를 개통 전에 실제로 돌려 검증해 두면 나중의 전환 작업에
-- 필요한 절차가 이미 확보된 셈이 된다.
--
-- 설계에서 지킨 두 가지가 있다. 첫째, 중단되어도 이어서 수행할 수 있다. 처리
-- 완료 지점을 작업 테이블에 남기므로 어디까지 했는지 잃어버리지 않는다. 둘째,
-- 일정 건수마다 끊어 커밋한다. 되돌리기 구간을 짧게 유지하여 장시간 잠금과
-- 되돌리기 영역 고갈을 피한다.
--
-- 제약: 현재 구현은 숫자형 단일 기본 키를 가진 테이블만 지원한다. 재시작 지점을
--       기본 키의 순서로 관리하기 때문이며, 문자형이나 복합 기본 키는 별도 확장이
--       필요하다. 대상 테이블이 이 조건을 만족하는지 먼저 확인할 것.

CREATE OR REPLACE PACKAGE PKG_REKEY AS

  PROCEDURE create_job(p_job_name      IN VARCHAR2,
                       p_owner_name    IN VARCHAR2,
                       p_table_name    IN VARCHAR2,
                       p_pk_column     IN VARCHAR2,
                       p_cipher_column IN VARCHAR2,
                       p_domain_code   IN VARCHAR2,
                       p_index_column  IN VARCHAR2 DEFAULT NULL,
                       p_batch_size    IN NUMBER   DEFAULT 1000);

  -- 한 번 호출에 p_max_batches 묶음만 처리하고 돌아온다. 업무 시간대를 피해
  -- 나누어 돌리기 위한 구조다.
  PROCEDURE run_job(p_job_name     IN VARCHAR2,
                    p_max_batches  IN NUMBER DEFAULT 10);

  PROCEDURE reset_job(p_job_name IN VARCHAR2);

  -- 남아 있는 옛 키 데이터의 건수. 0 이 되어야 옛 키를 폐기할 수 있다.
  FUNCTION remaining(p_job_name IN VARCHAR2) RETURN NUMBER;
END PKG_REKEY;
/

CREATE OR REPLACE PACKAGE BODY PKG_REKEY AS

  TYPE t_num_tab IS TABLE OF NUMBER;
  TYPE t_raw_tab IS TABLE OF RAW(32767);

  FUNCTION qualified(p_owner VARCHAR2, p_name VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    -- 동적 구문에 들어가는 식별자는 반드시 검증한다. 검증 없이 이어 붙이면
    -- 주입 통로가 된다.
    RETURN DBMS_ASSERT.ENQUOTE_NAME(DBMS_ASSERT.SIMPLE_SQL_NAME(p_owner), FALSE)
           || '.' || DBMS_ASSERT.ENQUOTE_NAME(DBMS_ASSERT.SIMPLE_SQL_NAME(p_name), FALSE);
  END qualified;

  FUNCTION col(p_name VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN DBMS_ASSERT.ENQUOTE_NAME(DBMS_ASSERT.SIMPLE_SQL_NAME(p_name), FALSE);
  END col;

  PROCEDURE create_job(p_job_name      IN VARCHAR2,
                       p_owner_name    IN VARCHAR2,
                       p_table_name    IN VARCHAR2,
                       p_pk_column     IN VARCHAR2,
                       p_cipher_column IN VARCHAR2,
                       p_domain_code   IN VARCHAR2,
                       p_index_column  IN VARCHAR2 DEFAULT NULL,
                       p_batch_size    IN NUMBER   DEFAULT 1000) IS
    v_key PKG_KEY_STORE.t_keyset;
  BEGIN
    PKG_AUTHZ.require_admin('REKEY');

    -- 목표는 언제나 현재 활성 키다. 작업 생성 시점에 고정하여, 작업 도중 키가
    -- 또 바뀌더라도 이번 작업의 목표는 흔들리지 않게 한다.
    v_key := PKG_KEY_STORE.get_active(p_domain_code);

    INSERT INTO SEC_REKEY_JOB (job_name, owner_name, table_name, pk_column,
                               cipher_column, index_column, domain_code,
                               target_key_id, batch_size, status)
    VALUES (p_job_name, UPPER(p_owner_name), UPPER(p_table_name), UPPER(p_pk_column),
            UPPER(p_cipher_column), UPPER(p_index_column), p_domain_code,
            v_key.key_id, p_batch_size, 'READY');

    PKG_AUDIT.log('REKEY_CREATE', 'ALERT', p_domain_code,
                  p_job_name || ' 대상 ' || UPPER(p_owner_name) || '.' || UPPER(p_table_name)
                  || ' 목표키 ' || v_key.key_id);
  END create_job;

  PROCEDURE reset_job(p_job_name IN VARCHAR2) IS
  BEGIN
    PKG_AUTHZ.require_admin('REKEY');
    UPDATE SEC_REKEY_JOB
       SET last_pk = NULL, done_cnt = 0, status = 'READY',
           last_error = NULL, updated_at = SYSTIMESTAMP
     WHERE job_name = p_job_name;
    PKG_AUDIT.log('REKEY_RESET', 'ALERT', NULL, p_job_name);
  END reset_job;

  FUNCTION remaining(p_job_name IN VARCHAR2) RETURN NUMBER IS
    v_job  SEC_REKEY_JOB%ROWTYPE;
    v_sql  VARCHAR2(2000);
    v_pks  t_num_tab;
    v_cips t_raw_tab;
    v_cnt  NUMBER := 0;
    v_last NUMBER := NULL;
  BEGIN
    SELECT * INTO v_job FROM SEC_REKEY_JOB WHERE job_name = p_job_name;

    -- 암호문 헤더의 키 식별자는 SQL 로 직접 걸러내기 어려우므로 읽어서 센다.
    -- 확인용이며 큰 테이블에서는 비용이 든다.
    v_sql := 'SELECT ' || col(v_job.pk_column) || ', ' || col(v_job.cipher_column)
             || ' FROM ' || qualified(v_job.owner_name, v_job.table_name)
             || ' WHERE ' || col(v_job.cipher_column) || ' IS NOT NULL'
             || '   AND (:last IS NULL OR ' || col(v_job.pk_column) || ' > :last)'
             || ' ORDER BY ' || col(v_job.pk_column)
             || ' FETCH FIRST :n ROWS ONLY';

    LOOP
      EXECUTE IMMEDIATE v_sql BULK COLLECT INTO v_pks, v_cips
        USING v_last, v_last, v_job.batch_size;
      EXIT WHEN v_pks.COUNT = 0;

      FOR i IN 1 .. v_pks.COUNT LOOP
        IF PKG_CRYPTO_FMT.key_id_of(v_cips(i)) <> v_job.target_key_id THEN
          v_cnt := v_cnt + 1;
        END IF;
      END LOOP;

      v_last := v_pks(v_pks.COUNT);
    END LOOP;

    RETURN v_cnt;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '작업 없음: ' || p_job_name);
      RETURN NULL;
  END remaining;

  PROCEDURE run_job(p_job_name IN VARCHAR2, p_max_batches IN NUMBER DEFAULT 10) IS
    v_job     SEC_REKEY_JOB%ROWTYPE;
    v_sel     VARCHAR2(2000);
    v_upd     VARCHAR2(2000);
    v_pks     t_num_tab;
    v_cips    t_raw_tab;
    v_up_pks  t_num_tab := t_num_tab();
    v_up_cips t_raw_tab := t_raw_tab();
    v_up_idx  t_raw_tab := t_raw_tab();
    v_last    NUMBER;
    v_plain   VARCHAR2(32767);
    v_done    NUMBER := 0;
  BEGIN
    PKG_AUTHZ.require_admin('REKEY');

    SELECT * INTO v_job FROM SEC_REKEY_JOB WHERE job_name = p_job_name FOR UPDATE;

    IF v_job.status = 'DONE' THEN
      RETURN;
    END IF;

    v_last := TO_NUMBER(v_job.last_pk);

    UPDATE SEC_REKEY_JOB
       SET status = 'RUNNING', started_at = NVL(started_at, SYSTIMESTAMP),
           updated_at = SYSTIMESTAMP
     WHERE job_name = p_job_name;
    COMMIT;

    v_sel := 'SELECT ' || col(v_job.pk_column) || ', ' || col(v_job.cipher_column)
             || ' FROM ' || qualified(v_job.owner_name, v_job.table_name)
             || ' WHERE ' || col(v_job.cipher_column) || ' IS NOT NULL'
             || '   AND (:last IS NULL OR ' || col(v_job.pk_column) || ' > :last)'
             || ' ORDER BY ' || col(v_job.pk_column)
             || ' FETCH FIRST :n ROWS ONLY';

    v_upd := 'UPDATE ' || qualified(v_job.owner_name, v_job.table_name)
             || ' SET ' || col(v_job.cipher_column) || ' = :c'
             || CASE WHEN v_job.index_column IS NOT NULL
                     THEN ', ' || col(v_job.index_column) || ' = :x' END
             || ' WHERE ' || col(v_job.pk_column) || ' = :k';

    FOR b IN 1 .. p_max_batches LOOP
      EXECUTE IMMEDIATE v_sel BULK COLLECT INTO v_pks, v_cips
        USING v_last, v_last, v_job.batch_size;
      EXIT WHEN v_pks.COUNT = 0;

      v_up_pks.DELETE; v_up_cips.DELETE; v_up_idx.DELETE;

      FOR i IN 1 .. v_pks.COUNT LOOP
        -- 이미 목표 키로 된 행은 건드리지 않는다. 중단 후 재실행이 안전한 이유다.
        IF PKG_CRYPTO_FMT.key_id_of(v_cips(i)) <> v_job.target_key_id THEN
          v_plain := PKG_CRYPTO_CORE.decrypt_str(v_cips(i));
          v_up_pks.EXTEND;  v_up_pks(v_up_pks.COUNT)  := v_pks(i);
          v_up_cips.EXTEND; v_up_cips(v_up_cips.COUNT) :=
            PKG_CRYPTO_CORE.encrypt_str(v_plain, v_job.domain_code);
          v_up_idx.EXTEND;  v_up_idx(v_up_idx.COUNT)  :=
            PKG_CRYPTO_CORE.blind_index(v_plain, v_job.domain_code);
        END IF;
      END LOOP;
      v_plain := NULL;   -- 평문을 변수에 오래 남겨 두지 않는다.

      IF v_up_pks.COUNT > 0 THEN
        IF v_job.index_column IS NOT NULL THEN
          FORALL i IN 1 .. v_up_pks.COUNT
            EXECUTE IMMEDIATE v_upd USING v_up_cips(i), v_up_idx(i), v_up_pks(i);
        ELSE
          FORALL i IN 1 .. v_up_pks.COUNT
            EXECUTE IMMEDIATE v_upd USING v_up_cips(i), v_up_pks(i);
        END IF;
        v_done := v_done + v_up_pks.COUNT;
      END IF;

      v_last := v_pks(v_pks.COUNT);

      -- 처리 지점을 업무 갱신과 같은 트랜잭션에서 커밋한다. 둘이 어긋나면
      -- 재시작 시 건너뛰거나 중복 처리하는 행이 생긴다.
      UPDATE SEC_REKEY_JOB
         SET last_pk = TO_CHAR(v_last), done_cnt = done_cnt + v_done,
             updated_at = SYSTIMESTAMP
       WHERE job_name = p_job_name;
      COMMIT;
      v_done := 0;

      EXIT WHEN v_pks.COUNT < v_job.batch_size;
    END LOOP;

    IF v_pks.COUNT < v_job.batch_size THEN
      UPDATE SEC_REKEY_JOB SET status = 'DONE', updated_at = SYSTIMESTAMP
       WHERE job_name = p_job_name;
      COMMIT;
      PKG_AUDIT.log('REKEY_DONE', 'ALERT', v_job.domain_code, p_job_name);
    ELSE
      UPDATE SEC_REKEY_JOB SET status = 'PAUSED', updated_at = SYSTIMESTAMP
       WHERE job_name = p_job_name;
      COMMIT;
    END IF;

  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '작업 없음: ' || p_job_name);
    WHEN OTHERS THEN
      ROLLBACK;
      UPDATE SEC_REKEY_JOB
         SET status = 'ERROR', last_error = SUBSTR(SQLERRM, 1, 400),
             updated_at = SYSTIMESTAMP
       WHERE job_name = p_job_name;
      COMMIT;
      PKG_AUDIT.log('REKEY_ERROR', 'ALERT', NULL, p_job_name || ': SQLCODE=' || SQLCODE);
      RAISE;
  END run_job;

END PKG_REKEY;
/
