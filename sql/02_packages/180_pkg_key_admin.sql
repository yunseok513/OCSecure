-- 키 관리
--
-- 키 교체는 서비스를 멈추지 않고 수행할 수 있어야 한다. 절차는 이렇다.
-- 새 키를 만들어 활성으로 올리면 기존 키는 자동으로 복호화 전용이 되고, 그 시점
-- 이후의 신규 데이터는 새 키로 암호화된다. 기존 데이터는 암호문 헤더의 키
-- 식별자를 보고 옛 키로 읽으므로 아무 일도 일어나지 않는다. 이어서 재암호화
-- 배치를 여유 시간대에 나누어 돌려 옛 키로 된 데이터를 모두 옮기고, 남은 것이
-- 없음이 확인되면 옛 키를 폐기한다.
--
-- 이 절차는 개통 전에 반드시 한 번 실제로 수행해 보아야 한다. 한 번도 돌려 보지
-- 않은 키 교체는 정작 필요한 순간에 반드시 실패한다.

CREATE OR REPLACE PACKAGE PKG_KEY_ADMIN AS

  PROCEDURE upsert_domain(p_domain_code     IN VARCHAR2,
                          p_description     IN VARCHAR2 DEFAULT NULL,
                          p_norm_mode       IN VARCHAR2 DEFAULT 'NONE',
                          p_mask_type       IN VARCHAR2 DEFAULT 'ALL',
                          p_require_app_ctx IN VARCHAR2 DEFAULT 'Y',
                          p_reveal_limit    IN NUMBER   DEFAULT 0,
                          p_audit_level     IN VARCHAR2 DEFAULT 'SUMMARY');

  -- 키를 새로 만든다. 세 벌(암호화용, 무결성용, 색인용)을 난수로 생성한다.
  FUNCTION create_key(p_domain_code IN VARCHAR2,
                      p_activate    IN BOOLEAN  DEFAULT FALSE,
                      p_note        IN VARCHAR2 DEFAULT NULL) RETURN PLS_INTEGER;

  -- 외부에서 생성한 키를 들여온다. 고정 시험 벡터 대조와 기존 시스템 이관에 쓴다.
  FUNCTION import_key(p_domain_code IN VARCHAR2,
                      p_enc_key     IN RAW,
                      p_mac_key     IN RAW,
                      p_idx_key     IN RAW,
                      p_alg_id      IN PLS_INTEGER DEFAULT NULL,
                      p_activate    IN BOOLEAN     DEFAULT FALSE,
                      p_note        IN VARCHAR2    DEFAULT NULL) RETURN PLS_INTEGER;

  PROCEDURE activate(p_key_id IN PLS_INTEGER);
  PROCEDURE retire  (p_key_id IN PLS_INTEGER);

  FUNCTION rotate(p_domain_code IN VARCHAR2,
                  p_note        IN VARCHAR2 DEFAULT NULL) RETURN PLS_INTEGER;

  -- 옛 키로 암호화된 데이터가 남아 있지 않은지 확인한 뒤에만 폐기해야 한다.
  PROCEDURE grant_reveal(p_domain_code IN VARCHAR2,
                         p_grantee     IN VARCHAR2,
                         p_type        IN VARCHAR2  DEFAULT 'ROLE',
                         p_expires_at  IN TIMESTAMP DEFAULT NULL,
                         p_reason      IN VARCHAR2  DEFAULT NULL);

  PROCEDURE revoke_reveal(p_domain_code IN VARCHAR2,
                          p_grantee     IN VARCHAR2,
                          p_type        IN VARCHAR2 DEFAULT 'ROLE');
END PKG_KEY_ADMIN;
/

CREATE OR REPLACE PACKAGE BODY PKG_KEY_ADMIN AS

  PROCEDURE upsert_domain(p_domain_code     IN VARCHAR2,
                          p_description     IN VARCHAR2 DEFAULT NULL,
                          p_norm_mode       IN VARCHAR2 DEFAULT 'NONE',
                          p_mask_type       IN VARCHAR2 DEFAULT 'ALL',
                          p_require_app_ctx IN VARCHAR2 DEFAULT 'Y',
                          p_reveal_limit    IN NUMBER   DEFAULT 0,
                          p_audit_level     IN VARCHAR2 DEFAULT 'SUMMARY') IS
  BEGIN
    PKG_AUTHZ.require_admin('POLICY_ADMIN');

    MERGE INTO SEC_DOMAIN t
    USING (SELECT p_domain_code AS domain_code FROM DUAL) s
    ON (t.domain_code = s.domain_code)
    WHEN MATCHED THEN
      UPDATE SET t.description     = NVL(p_description, t.description),
                 t.norm_mode       = p_norm_mode,
                 t.mask_type       = p_mask_type,
                 t.require_app_ctx = p_require_app_ctx,
                 t.reveal_limit    = p_reveal_limit,
                 t.audit_level     = p_audit_level
    WHEN NOT MATCHED THEN
      INSERT (domain_code, description, norm_mode, mask_type,
              require_app_ctx, reveal_limit, audit_level)
      VALUES (p_domain_code, p_description, p_norm_mode, p_mask_type,
              p_require_app_ctx, p_reveal_limit, p_audit_level);

    PKG_KEY_STORE.flush_cache;
    PKG_AUDIT.log('DOMAIN_UPSERT', 'INFO', p_domain_code,
                  '정규화=' || p_norm_mode || ' 마스킹=' || p_mask_type
                  || ' 문맥필수=' || p_require_app_ctx || ' 임계치=' || p_reveal_limit);
  END upsert_domain;

  FUNCTION next_key_id RETURN PLS_INTEGER IS
    v PLS_INTEGER;
  BEGIN
    SELECT SEQ_SEC_KEY_ID.NEXTVAL INTO v FROM DUAL;
    RETURN v;
  END next_key_id;

  FUNCTION insert_key(p_domain_code IN VARCHAR2,
                      p_enc_key     IN RAW,
                      p_mac_key     IN RAW,
                      p_idx_key     IN RAW,
                      p_alg_id      IN PLS_INTEGER,
                      p_note        IN VARCHAR2) RETURN PLS_INTEGER IS
    v_id  PLS_INTEGER := next_key_id;
    v_alg PLS_INTEGER;
  BEGIN
    IF UTL_RAW.LENGTH(p_enc_key) <> 32
       OR UTL_RAW.LENGTH(p_mac_key) <> 32
       OR UTL_RAW.LENGTH(p_idx_key) <> 32 THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg, '키 길이는 각 32바이트여야 한다');
    END IF;

    BEGIN
      SELECT NVL(p_alg_id, alg_id) INTO v_alg
        FROM SEC_DOMAIN WHERE domain_code = p_domain_code;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_domain, p_domain_code);
    END;

    INSERT INTO SEC_KEY (key_id, domain_code, alg_id, key_state,
                         enc_key_wrapped, mac_key_wrapped, idx_key_wrapped, note)
    VALUES (v_id, p_domain_code, v_alg, 'RETIRING',
            PKG_KEY_STORE.wrap(p_enc_key),
            PKG_KEY_STORE.wrap(p_mac_key),
            PKG_KEY_STORE.wrap(p_idx_key),
            p_note);

    -- 처음에는 복호화 전용으로 들어간다. 활성화는 별도의 명시적 행위여야 한다.
    RETURN v_id;
  END insert_key;

  FUNCTION create_key(p_domain_code IN VARCHAR2,
                      p_activate    IN BOOLEAN  DEFAULT FALSE,
                      p_note        IN VARCHAR2 DEFAULT NULL) RETURN PLS_INTEGER IS
    v_id PLS_INTEGER;
  BEGIN
    PKG_AUTHZ.require_admin('KEY_ADMIN');
    v_id := insert_key(p_domain_code,
                       PKG_PROVIDER_DBMS.random_bytes(32),
                       PKG_PROVIDER_DBMS.random_bytes(32),
                       PKG_PROVIDER_DBMS.random_bytes(32),
                       NULL, p_note);
    PKG_AUDIT.log('KEY_CREATE', 'ALERT', p_domain_code, '키 식별자 ' || v_id);
    IF p_activate THEN
      activate(v_id);
    END IF;
    RETURN v_id;
  END create_key;

  FUNCTION import_key(p_domain_code IN VARCHAR2,
                      p_enc_key     IN RAW,
                      p_mac_key     IN RAW,
                      p_idx_key     IN RAW,
                      p_alg_id      IN PLS_INTEGER DEFAULT NULL,
                      p_activate    IN BOOLEAN     DEFAULT FALSE,
                      p_note        IN VARCHAR2    DEFAULT NULL) RETURN PLS_INTEGER IS
    v_id PLS_INTEGER;
  BEGIN
    PKG_AUTHZ.require_admin('KEY_ADMIN');
    v_id := insert_key(p_domain_code, p_enc_key, p_mac_key, p_idx_key, p_alg_id, p_note);
    PKG_AUDIT.log('KEY_IMPORT', 'ALERT', p_domain_code, '키 식별자 ' || v_id);
    IF p_activate THEN
      activate(v_id);
    END IF;
    RETURN v_id;
  END import_key;

  PROCEDURE activate(p_key_id IN PLS_INTEGER) IS
    v_domain VARCHAR2(30);
  BEGIN
    PKG_AUTHZ.require_admin('KEY_ADMIN');

    SELECT domain_code INTO v_domain FROM SEC_KEY WHERE key_id = p_key_id;

    -- 기존 활성 키를 먼저 내린다. 도메인당 활성 키가 둘이 되는 순간을 만들지 않기
    -- 위해 순서가 중요하다.
    UPDATE SEC_KEY
       SET key_state = 'RETIRING'
     WHERE domain_code = v_domain
       AND key_state   = 'ACTIVE'
       AND key_id     <> p_key_id;

    UPDATE SEC_KEY
       SET key_state    = 'ACTIVE',
           activated_at = SYSTIMESTAMP,
           retired_at   = NULL
     WHERE key_id = p_key_id;

    PKG_KEY_STORE.flush_cache;
    PKG_AUDIT.log('KEY_ACTIVATE', 'ALERT', v_domain, '키 식별자 ' || p_key_id);
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_key_missing, '키 식별자 없음: ' || p_key_id);
  END activate;

  PROCEDURE retire(p_key_id IN PLS_INTEGER) IS
    v_domain VARCHAR2(30);
    v_state  VARCHAR2(10);
  BEGIN
    PKG_AUTHZ.require_admin('KEY_ADMIN');

    SELECT domain_code, key_state INTO v_domain, v_state
      FROM SEC_KEY WHERE key_id = p_key_id;

    IF v_state = 'ACTIVE' THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_bad_arg,
        '활성 키는 폐기할 수 없다. 먼저 다른 키를 활성화할 것');
    END IF;

    -- 폐기하면 이 키로 암호화된 데이터는 더 이상 읽을 수 없다. 재암호화가 모두
    -- 끝났는지 확인한 뒤에 호출해야 한다.
    UPDATE SEC_KEY
       SET key_state = 'RETIRED', retired_at = SYSTIMESTAMP
     WHERE key_id = p_key_id;

    PKG_KEY_STORE.flush_cache;
    PKG_AUDIT.log('KEY_RETIRE', 'ALERT', v_domain, '키 식별자 ' || p_key_id);
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_key_missing, '키 식별자 없음: ' || p_key_id);
  END retire;

  FUNCTION rotate(p_domain_code IN VARCHAR2,
                  p_note        IN VARCHAR2 DEFAULT NULL) RETURN PLS_INTEGER IS
  BEGIN
    RETURN create_key(p_domain_code, TRUE, NVL(p_note, '정기 교체'));
  END rotate;

  PROCEDURE grant_reveal(p_domain_code IN VARCHAR2,
                         p_grantee     IN VARCHAR2,
                         p_type        IN VARCHAR2  DEFAULT 'ROLE',
                         p_expires_at  IN TIMESTAMP DEFAULT NULL,
                         p_reason      IN VARCHAR2  DEFAULT NULL) IS
  BEGIN
    PKG_AUTHZ.require_admin('POLICY_ADMIN');

    MERGE INTO SEC_REVEAL_GRANT t
    USING (SELECT p_domain_code AS domain_code, p_type AS grantee_type,
                  UPPER(p_grantee) AS grantee_name FROM DUAL) s
    ON (t.domain_code = s.domain_code AND t.grantee_type = s.grantee_type
        AND t.grantee_name = s.grantee_name)
    WHEN MATCHED THEN
      UPDATE SET t.expires_at = p_expires_at, t.reason = p_reason,
                 t.granted_at = SYSTIMESTAMP
    WHEN NOT MATCHED THEN
      INSERT (domain_code, grantee_type, grantee_name, expires_at, reason)
      VALUES (s.domain_code, s.grantee_type, s.grantee_name, p_expires_at, p_reason);

    PKG_AUDIT.log('REVEAL_GRANT', 'ALERT', p_domain_code,
                  p_type || ' ' || UPPER(p_grantee)
                  || CASE WHEN p_expires_at IS NOT NULL
                          THEN ' 만료 ' || TO_CHAR(p_expires_at, 'YYYY-MM-DD HH24:MI')
                          ELSE ' 만료 없음' END);
  END grant_reveal;

  PROCEDURE revoke_reveal(p_domain_code IN VARCHAR2,
                          p_grantee     IN VARCHAR2,
                          p_type        IN VARCHAR2 DEFAULT 'ROLE') IS
  BEGIN
    PKG_AUTHZ.require_admin('POLICY_ADMIN');
    DELETE FROM SEC_REVEAL_GRANT
     WHERE domain_code  = p_domain_code
       AND grantee_type = p_type
       AND grantee_name = UPPER(p_grantee);
    PKG_AUDIT.log('REVEAL_REVOKE', 'ALERT', p_domain_code, p_type || ' ' || UPPER(p_grantee));
  END revoke_reveal;

END PKG_KEY_ADMIN;
/
