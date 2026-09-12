-- OCSecure 자체 시험
-- OCS_OWNER 계정으로 실행한다. 설치 직후와 변경 배포 직후에 반드시 돌린다.
--
-- 이 시험의 핵심은 고정 시험 벡터 대조다. 참조 구현(tools/refimpl/ocsecure_ref.py)이
-- 만들어 낸 값과 PL/SQL 의 계산 결과가 바이트 단위로 같은지 확인한다. 둘이 같으면
-- 암호문 포맷이 규격대로 구현되었다고 볼 수 있고, 나중에 자바 등 다른 계층이
-- 같은 데이터를 읽어야 할 때도 이 벡터가 기준이 된다.
--
-- 시험을 위해 설정을 개발 모드로 잠시 바꾼다. 끝나면 원래대로 되돌린다.
-- 운영계에서는 실행하지 말 것.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET FEEDBACK OFF

DECLARE
  v_pass  PLS_INTEGER := 0;
  v_fail  PLS_INTEGER := 0;
  v_kek_src  VARCHAR2(200);
  v_ctx_mode VARCHAR2(200);

  v_c      RAW(2000);
  v_c2     RAW(2000);
  v_bad    RAW(2000);
  v_s      VARCHAR2(4000);
  v_n      NUMBER;
  v_kid    PLS_INTEGER;

  FUNCTION kat(p_name VARCHAR2) RETURN VARCHAR2 IS
    v VARCHAR2(4000);
  BEGIN
    SELECT kat_value INTO v FROM SEC_KAT WHERE kat_name = p_name;
    RETURN v;
  END kat;

  FUNCTION katr(p_name VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN HEXTORAW(kat(p_name));
  END katr;

  PROCEDURE chk(p_name VARCHAR2, p_ok BOOLEAN, p_note VARCHAR2 DEFAULT NULL) IS
  BEGIN
    IF p_ok THEN
      v_pass := v_pass + 1;
      DBMS_OUTPUT.PUT_LINE('  [통과] ' || p_name);
    ELSE
      v_fail := v_fail + 1;
      DBMS_OUTPUT.PUT_LINE('  [실패] ' || p_name
                           || CASE WHEN p_note IS NOT NULL THEN ' :: ' || p_note END);
    END IF;
  END chk;

  PROCEDURE put_key(p_key_id PLS_INTEGER, p_domain VARCHAR2, p_state VARCHAR2) IS
  BEGIN
    INSERT INTO SEC_KEY (key_id, domain_code, alg_id, key_state,
                         enc_key_wrapped, mac_key_wrapped, idx_key_wrapped,
                         activated_at, note)
    VALUES (p_key_id, p_domain, PKG_PROVIDER_DBMS.c_alg_aes256_cbc, p_state,
            PKG_KEY_STORE.wrap(katr('ENC_KEY')),
            PKG_KEY_STORE.wrap(katr('MAC_KEY')),
            PKG_KEY_STORE.wrap(katr('IDX_KEY')),
            SYSTIMESTAMP, '자체 시험용 고정 키');
  END put_key;

  PROCEDURE cleanup IS
  BEGIN
    DELETE FROM SEC_REVEAL_GRANT WHERE domain_code LIKE 'KAT%';
    DELETE FROM SEC_KEY          WHERE domain_code LIKE 'KAT%';
    DELETE FROM SEC_DOMAIN       WHERE domain_code LIKE 'KAT%';
    DELETE FROM SEC_ADMIN_GRANT  WHERE grantee_type = 'USER'
                                   AND grantee_name = SYS_CONTEXT('USERENV','SESSION_USER')
                                   AND reason = '자체 시험';
    COMMIT;
  END cleanup;

BEGIN
  DBMS_OUTPUT.PUT_LINE('=== OCSecure 자체 시험 ===');
  DBMS_OUTPUT.PUT_LINE('경고: 설정을 개발 모드로 잠시 바꾼다. 운영계에서 실행하지 말 것.');

  ------------------------------------------------------------------ 준비
  SELECT cfg_value INTO v_kek_src  FROM SEC_CONFIG WHERE cfg_key = 'KEK_SOURCE';
  SELECT cfg_value INTO v_ctx_mode FROM SEC_CONFIG WHERE cfg_key = 'APPCTX_MODE';
  UPDATE SEC_CONFIG SET cfg_value = 'GLOBAL_CTX' WHERE cfg_key = 'KEK_SOURCE';
  UPDATE SEC_CONFIG SET cfg_value = 'SIMPLE'     WHERE cfg_key = 'APPCTX_MODE';
  COMMIT;

  cleanup;
  PKG_KEK_PROVIDER.close_keystore;
  PKG_KEK_PROVIDER.set_master_key(katr('KEK'));
  PKG_KEY_STORE.flush_cache;

  INSERT INTO SEC_ADMIN_GRANT (privilege, grantee_type, grantee_name, reason)
  VALUES ('KEY_ADMIN', 'USER', SYS_CONTEXT('USERENV','SESSION_USER'), '자체 시험');
  INSERT INTO SEC_ADMIN_GRANT (privilege, grantee_type, grantee_name, reason)
  VALUES ('POLICY_ADMIN', 'USER', SYS_CONTEXT('USERENV','SESSION_USER'), '자체 시험');
  COMMIT;

  PKG_KEY_ADMIN.upsert_domain('KAT_NONE',   '시험: 정규화 없음', 'NONE',  'ALL', 'N', 0, 'NONE');
  PKG_KEY_ADMIN.upsert_domain('KAT_DIGITS', '시험: 숫자만',      'DIGITS','RRN', 'N', 0, 'NONE');
  PKG_KEY_ADMIN.upsert_domain('KAT_TRIM',   '시험: 공백 제거',   'TRIM',  'NAME','N', 0, 'NONE');
  PKG_KEY_ADMIN.upsert_domain('KAT_SEC',    '시험: 통제 확인',   'NONE',  'ALL', 'Y', 0, 'NONE');
  PKG_KEY_ADMIN.upsert_domain('KAT_LIMIT',  '시험: 임계치',      'NONE',  'ALL', 'N', 2, 'NONE');

  -- 키 식별자 1~99 는 시험용으로 예약되어 있다(운영 키는 100번부터).
  put_key(1, 'KAT_NONE',   'ACTIVE');
  put_key(2, 'KAT_DIGITS', 'ACTIVE');
  put_key(3, 'KAT_TRIM',   'ACTIVE');
  put_key(5, 'KAT_SEC',    'ACTIVE');
  put_key(6, 'KAT_LIMIT',  'ACTIVE');
  COMMIT;
  PKG_KEY_STORE.flush_cache;

  ------------------------------------------------------- 1. 키 래핑 왕복
  chk('마스터 키로 감싼 데이터 키가 그대로 풀린다',
      PKG_KEY_STORE.unwrap(PKG_KEY_STORE.wrap(katr('ENC_KEY'))) = katr('ENC_KEY'));

  chk('참조 구현이 감싼 키를 그대로 풀 수 있다',
      PKG_KEY_STORE.unwrap(katr('WRAPPED_ENC_KEY')) = katr('ENC_KEY'),
      '참조 구현과 래핑 규칙이 다르다');

  ------------------------------------------- 2. 고정 벡터 대조 (암호화)
  v_c := PKG_CRYPTO_CORE.encrypt_str(kat('PLAIN_RRN'), 'KAT_NONE', katr('IV'));
  chk('고정 IV 암호화 결과가 참조 구현과 일치한다 (주민등록번호)',
      v_c = katr('CIPHER_RRN'),
      '계산 ' || RAWTOHEX(v_c) || ' / 기대 ' || kat('CIPHER_RRN'));

  v_c := PKG_CRYPTO_CORE.encrypt_str(kat('PLAIN_ADDR'), 'KAT_NONE', katr('IV'));
  chk('고정 IV 암호화 결과가 참조 구현과 일치한다 (한글 주소)',
      v_c = katr('CIPHER_ADDR'),
      '계산 ' || RAWTOHEX(v_c));

  v_c := PKG_CRYPTO_CORE.encrypt_str(kat('PLAIN_LONG'), 'KAT_NONE', katr('IV'));
  chk('고정 IV 암호화 결과가 참조 구현과 일치한다 (긴 문자열)',
      v_c = katr('CIPHER_LONG'));

  ------------------------------------------- 3. 고정 벡터 대조 (복호화)
  chk('참조 구현이 만든 암호문을 복호화하면 원문이 나온다 (주민등록번호)',
      PKG_CRYPTO_CORE.decrypt_str(katr('CIPHER_RRN')) = kat('PLAIN_RRN'));

  chk('참조 구현이 만든 암호문을 복호화하면 원문이 나온다 (한글 주소)',
      PKG_CRYPTO_CORE.decrypt_str(katr('CIPHER_ADDR')) = kat('PLAIN_ADDR'),
      '문자집합 변환 경로를 확인할 것');

  chk('참조 구현이 만든 암호문을 복호화하면 원문이 나온다 (성명)',
      PKG_CRYPTO_CORE.decrypt_str(katr('CIPHER_NAME')) = kat('PLAIN_NAME'));

  ------------------------------------------------------- 4. 암호문 길이
  v_c := PKG_CRYPTO_CORE.encrypt_str('880101-1234567', 'KAT_NONE');
  chk('주민등록번호 암호문 길이가 설계 산정치(68바이트)와 같다',
      UTL_RAW.LENGTH(v_c) = 68, '실제 ' || UTL_RAW.LENGTH(v_c));

  ------------------------------------------------------- 5. 확률적 암호화
  v_c  := PKG_CRYPTO_CORE.encrypt_str('880101-1234567', 'KAT_NONE');
  v_c2 := PKG_CRYPTO_CORE.encrypt_str('880101-1234567', 'KAT_NONE');
  chk('같은 평문을 두 번 암호화하면 서로 다른 암호문이 된다', v_c <> v_c2);
  chk('그럼에도 둘 다 같은 원문으로 복호화된다',
      PKG_CRYPTO_CORE.decrypt_str(v_c) = PKG_CRYPTO_CORE.decrypt_str(v_c2));

  ------------------------------------------------------- 6. 변조 탐지
  v_bad := UTL_RAW.CONCAT(UTL_RAW.SUBSTR(v_c, 1, 24),
                          UTL_RAW.BIT_XOR(UTL_RAW.SUBSTR(v_c, 25, 1), HEXTORAW('01')),
                          UTL_RAW.SUBSTR(v_c, 26));
  BEGIN
    v_s := PKG_CRYPTO_CORE.decrypt_str(v_bad);
    chk('암호문 한 바이트를 바꾸면 복호화가 거부된다', FALSE, '예외가 발생하지 않았다');
  EXCEPTION
    WHEN OTHERS THEN
      chk('암호문 한 바이트를 바꾸면 복호화가 거부된다',
          SQLCODE = PKG_SEC_ERR.e_integrity, 'SQLCODE=' || SQLCODE);
  END;

  ------------------------------------------------------- 7. 블라인드 인덱스
  chk('색인 값이 참조 구현과 일치한다 (정규화 없음)',
      PKG_CRYPTO_CORE.blind_index(kat('PLAIN_ADDR'), 'KAT_NONE') = katr('BIDX_ADDR'));

  chk('색인 값이 참조 구현과 일치한다 (숫자만 남김)',
      PKG_CRYPTO_CORE.blind_index(kat('PLAIN_RRN'), 'KAT_DIGITS') = katr('BIDX_RRN'));

  chk('색인 값이 참조 구현과 일치한다 (공백 제거)',
      PKG_CRYPTO_CORE.blind_index(kat('PLAIN_NAME'), 'KAT_TRIM') = katr('BIDX_NAME'));

  chk('구분자가 있든 없든 같은 색인 값이 나온다',
      PKG_CRYPTO_CORE.blind_index('880101-1234567', 'KAT_DIGITS')
        = PKG_CRYPTO_CORE.blind_index('8801011234567', 'KAT_DIGITS'));

  chk('색인 값은 결정적이다',
      PKG_CRYPTO_CORE.blind_index('880101-1234567', 'KAT_DIGITS')
        = PKG_CRYPTO_CORE.blind_index('880101-1234567', 'KAT_DIGITS'));

  ------------------------------------------------------- 8. 비밀번호
  chk('비밀번호 해시가 참조 구현과 일치한다',
      PKG_CRYPTO_CORE.pwd_hash(kat('PWD_PLAIN_0'), katr('PWD_SALT'),
                               TO_NUMBER(kat('PWD_ITER'))) = katr('PWD_STORED_0'),
      '계산 ' || RAWTOHEX(PKG_CRYPTO_CORE.pwd_hash(kat('PWD_PLAIN_0'),
                          katr('PWD_SALT'), TO_NUMBER(kat('PWD_ITER')))));

  chk('한글 비밀번호 해시가 참조 구현과 일치한다',
      PKG_CRYPTO_CORE.pwd_hash(kat('PWD_PLAIN_1'), katr('PWD_SALT'),
                               TO_NUMBER(kat('PWD_ITER'))) = katr('PWD_STORED_1'));

  chk('올바른 비밀번호는 검증을 통과한다',
      PKG_CRYPTO_CORE.pwd_verify(kat('PWD_PLAIN_0'), katr('PWD_STORED_0')));

  chk('틀린 비밀번호는 검증을 통과하지 못한다',
      NOT PKG_CRYPTO_CORE.pwd_verify(kat('PWD_PLAIN_0') || 'x', katr('PWD_STORED_0')));

  chk('같은 비밀번호라도 저장값은 매번 달라진다 (솔트)',
      PKG_CRYPTO_CORE.pwd_hash('Passw0rd!') <> PKG_CRYPTO_CORE.pwd_hash('Passw0rd!'));

  ------------------------------------------------------- 9. 키 교체
  v_c := PKG_CRYPTO_CORE.encrypt_str('교체 전 데이터', 'KAT_NONE');
  put_key(4, 'KAT_NONE', 'RETIRING');
  COMMIT;
  PKG_KEY_ADMIN.activate(4);

  v_c2 := PKG_CRYPTO_CORE.encrypt_str('교체 후 데이터', 'KAT_NONE');
  chk('교체 후 신규 암호화는 새 키를 쓴다',
      PKG_CRYPTO_FMT.key_id_of(v_c2) = 4,
      '키 식별자 ' || PKG_CRYPTO_FMT.key_id_of(v_c2));
  chk('교체 전 데이터는 여전히 복호화된다',
      PKG_CRYPTO_CORE.decrypt_str(v_c) = '교체 전 데이터');

  SELECT COUNT(*) INTO v_n FROM SEC_KEY
   WHERE domain_code = 'KAT_NONE' AND key_state = 'ACTIVE';
  chk('도메인당 활성 키는 하나뿐이다', v_n = 1, '활성 키 ' || v_n || '개');

  ------------------------------------------------- 10. 문맥 없는 복호화 거부
  v_c := PKG_CRYPTO_POLICY.protect('KAT_SEC', '통제 시험 값');
  PKG_APP_CONTEXT.clear_identity;
  BEGIN
    v_s := PKG_CRYPTO_POLICY.reveal('KAT_SEC', v_c);
    chk('애플리케이션 문맥이 없으면 복호화가 거부된다', FALSE, '예외가 발생하지 않았다');
  EXCEPTION
    WHEN OTHERS THEN
      chk('애플리케이션 문맥이 없으면 복호화가 거부된다',
          SQLCODE = PKG_SEC_ERR.e_no_app_ctx, 'SQLCODE=' || SQLCODE);
  END;

  ------------------------------------------------- 11. 권한 없는 복호화 거부
  PKG_SECURE_API.login('시험사용자');
  BEGIN
    v_s := PKG_CRYPTO_POLICY.reveal('KAT_SEC', v_c);
    chk('복호화 권한이 없으면 거부된다', FALSE, '예외가 발생하지 않았다');
  EXCEPTION
    WHEN OTHERS THEN
      chk('복호화 권한이 없으면 거부된다',
          SQLCODE = PKG_SEC_ERR.e_no_reveal, 'SQLCODE=' || SQLCODE);
  END;

  chk('거부되어도 마스킹된 값은 얻을 수 있다',
      PKG_CRYPTO_POLICY.reveal_or_mask('KAT_SEC', v_c) = '********');

  ------------------------------------------------- 12. 권한 부여 후 복호화
  PKG_KEY_ADMIN.grant_reveal('KAT_SEC', SYS_CONTEXT('USERENV','SESSION_USER'),
                             'USER', NULL, '자체 시험');
  chk('권한을 부여하면 복호화된다',
      PKG_CRYPTO_POLICY.reveal('KAT_SEC', v_c) = '통제 시험 값');

  ------------------------------------------------- 13. 만료된 한시 권한
  PKG_KEY_ADMIN.grant_reveal('KAT_SEC', SYS_CONTEXT('USERENV','SESSION_USER'),
                             'USER', SYSTIMESTAMP - INTERVAL '1' HOUR, '자체 시험');
  BEGIN
    v_s := PKG_CRYPTO_POLICY.reveal('KAT_SEC', v_c);
    chk('만료된 한시 권한은 인정되지 않는다', FALSE, '예외가 발생하지 않았다');
  EXCEPTION
    WHEN OTHERS THEN
      chk('만료된 한시 권한은 인정되지 않는다',
          SQLCODE = PKG_SEC_ERR.e_no_reveal, 'SQLCODE=' || SQLCODE);
  END;

  ------------------------------------------------- 14. 사용량 임계치
  PKG_KEY_ADMIN.grant_reveal('KAT_LIMIT', SYS_CONTEXT('USERENV','SESSION_USER'),
                             'USER', NULL, '자체 시험');
  v_c := PKG_CRYPTO_POLICY.protect('KAT_LIMIT', '임계치 시험');
  DELETE FROM SEC_REVEAL_USAGE WHERE domain_code = 'KAT_LIMIT';
  COMMIT;
  v_s := PKG_CRYPTO_POLICY.reveal('KAT_LIMIT', v_c);
  v_s := PKG_CRYPTO_POLICY.reveal('KAT_LIMIT', v_c);
  BEGIN
    v_s := PKG_CRYPTO_POLICY.reveal('KAT_LIMIT', v_c);
    chk('임계치를 넘는 복호화는 차단된다', FALSE, '예외가 발생하지 않았다');
  EXCEPTION
    WHEN OTHERS THEN
      chk('임계치를 넘는 복호화는 차단된다',
          SQLCODE = PKG_SEC_ERR.e_rate_limit, 'SQLCODE=' || SQLCODE);
  END;

  ------------------------------------------------- 15. 마스킹 규칙
  chk('주민등록번호 마스킹',
      PKG_CRYPTO_POLICY.mask_value('RRN', '880101-1234567') = '880101-1******',
      PKG_CRYPTO_POLICY.mask_value('RRN', '880101-1234567'));
  chk('성명 마스킹 (세 글자)',
      PKG_CRYPTO_POLICY.mask_value('NAME', '홍길동') = '홍*동',
      PKG_CRYPTO_POLICY.mask_value('NAME', '홍길동'));
  chk('성명 마스킹 (두 글자)',
      PKG_CRYPTO_POLICY.mask_value('NAME', '이순') = '이*');
  chk('계좌번호 마스킹',
      PKG_CRYPTO_POLICY.mask_value('ACCOUNT', '110123456789') = '********6789',
      PKG_CRYPTO_POLICY.mask_value('ACCOUNT', '110123456789'));

  ------------------------------------------------- 16. 널 처리
  chk('널을 암호화하면 널이 나온다',  PKG_CRYPTO_CORE.encrypt_str(NULL, 'KAT_NONE') IS NULL);
  chk('널을 복호화하면 널이 나온다',  PKG_CRYPTO_CORE.decrypt_str(NULL) IS NULL);
  chk('널의 색인 값은 널이다',        PKG_CRYPTO_CORE.blind_index(NULL, 'KAT_NONE') IS NULL);

  ------------------------------------------------- 17. 감사 기록
  SELECT COUNT(*) INTO v_n FROM SEC_AUDIT_LOG
   WHERE event_type = 'REVEAL_DENIED' AND event_ts > SYSTIMESTAMP - INTERVAL '10' MINUTE;
  chk('거부된 복호화 시도가 감사 기록에 남는다', v_n >= 2, '기록 ' || v_n || '건');

  SELECT COUNT(*) INTO v_n FROM SEC_AUDIT_LOG
   WHERE event_ts > SYSTIMESTAMP - INTERVAL '10' MINUTE
     AND (UPPER(detail) LIKE '%880101%' OR detail LIKE '%홍길동%');
  chk('감사 기록에 평문이 남지 않는다', v_n = 0, '평문이 포함된 기록 ' || v_n || '건');

  ------------------------------------------------------------------ 정리
  PKG_SECURE_API.logout;
  cleanup;
  PKG_KEK_PROVIDER.close_keystore;
  UPDATE SEC_CONFIG SET cfg_value = v_kek_src  WHERE cfg_key = 'KEK_SOURCE';
  UPDATE SEC_CONFIG SET cfg_value = v_ctx_mode WHERE cfg_key = 'APPCTX_MODE';
  COMMIT;

  DBMS_OUTPUT.PUT_LINE('=== 통과 ' || v_pass || ' / 실패 ' || v_fail || ' ===');
  DBMS_OUTPUT.PUT_LINE('설정을 원래대로 되돌렸다: KEK_SOURCE=' || v_kek_src
                       || ', APPCTX_MODE=' || v_ctx_mode);

  IF v_fail > 0 THEN
    RAISE_APPLICATION_ERROR(-20998, '자체 시험 실패 ' || v_fail || '건. 배포하지 말 것.');
  END IF;

EXCEPTION
  WHEN OTHERS THEN
    -- 시험이 중간에 죽어도 설정은 반드시 되돌린다.
    BEGIN
      cleanup;
      PKG_KEK_PROVIDER.close_keystore;
      UPDATE SEC_CONFIG SET cfg_value = NVL(v_kek_src,  'EXTERNAL') WHERE cfg_key = 'KEK_SOURCE';
      UPDATE SEC_CONFIG SET cfg_value = NVL(v_ctx_mode, 'PROOF')    WHERE cfg_key = 'APPCTX_MODE';
      COMMIT;
    EXCEPTION
      WHEN OTHERS THEN NULL;
    END;
    RAISE;
END;
/

SET FEEDBACK ON
