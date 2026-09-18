-- 권한 부여
-- OCS_OWNER 계정으로 실행한다.
--
-- 원칙은 두 가지다. 첫째, 최상위 인터페이스 패키지에만 실행 권한을 준다.
-- 둘째, 그 아래 계층에는 어떤 계정에도 권한을 주지 않는다. 정책 계층을 우회한
-- 복호화가 불가능한 것은 전적으로 둘째 원칙 덕분이므로, 운영 중에 이 원칙이
-- 깨지지 않았는지 정기적으로 확인해야 한다. 확인 구문은 이 파일 끝에 있다.

-- 응용 계정 -------------------------------------------------------------------
GRANT EXECUTE ON PKG_SECURE_API TO OCS_ROLE_APP;
-- 뷰 정의에서 참조하는 객체의 권한은 역할로는 인정되지 않으므로 직접 부여한다.
-- 투명화 뷰를 응용 스키마에 만들려면 이 부여가 필요하다.
GRANT EXECUTE ON PKG_SECURE_API TO OCS_APP;

-- 키 관리자 -------------------------------------------------------------------
GRANT EXECUTE ON PKG_KEY_ADMIN    TO OCS_ROLE_KEYADM;
GRANT EXECUTE ON PKG_REKEY        TO OCS_ROLE_KEYADM;
GRANT EXECUTE ON PKG_KEK_PROVIDER TO OCS_ROLE_KEYADM;   -- 개발 환경의 마스터 키 주입용
GRANT SELECT  ON V_SEC_KEY_STATUS TO OCS_ROLE_KEYADM;

-- 감사자 -----------------------------------------------------------------------
GRANT SELECT ON SEC_AUDIT_LOG          TO OCS_ROLE_AUDITOR;
GRANT SELECT ON SEC_REVEAL_USAGE       TO OCS_ROLE_AUDITOR;
GRANT SELECT ON V_SEC_EFFECTIVE_REVEAL TO OCS_ROLE_AUDITOR;
GRANT SELECT ON V_SEC_KEY_STATUS       TO OCS_ROLE_AUDITOR;
GRANT SELECT ON SEC_DOMAIN             TO OCS_ROLE_AUDITOR;
GRANT SELECT ON SEC_ADMIN_GRANT        TO OCS_ROLE_AUDITOR;

-- 관리 권한 대장 초기 등록 -------------------------------------------------------
-- 이후의 변경은 반드시 이 대장을 통해서만 이루어져야 하며, 변경 자체가 감사 대상이다.
INSERT INTO SEC_ADMIN_GRANT (privilege, grantee_type, grantee_name, reason)
VALUES ('KEY_ADMIN', 'ROLE', 'OCS_ROLE_KEYADM', '설치 시 초기 등록');
INSERT INTO SEC_ADMIN_GRANT (privilege, grantee_type, grantee_name, reason)
VALUES ('REKEY', 'ROLE', 'OCS_ROLE_KEYADM', '설치 시 초기 등록');
INSERT INTO SEC_ADMIN_GRANT (privilege, grantee_type, grantee_name, reason)
VALUES ('POLICY_ADMIN', 'ROLE', 'OCS_ROLE_KEYADM', '설치 시 초기 등록');
COMMIT;

-- 점검 구문 ---------------------------------------------------------------------
-- 아래 조회 결과는 항상 비어 있어야 한다. 한 건이라도 나오면 정책 계층을 우회한
-- 복호화가 가능한 상태이므로 즉시 회수해야 한다.
PROMPT
PROMPT === 하위 계층에 새어 나간 실행 권한 점검 (결과가 비어 있어야 정상) ===
SELECT grantee, table_name AS object_name, privilege
  FROM USER_TAB_PRIVS
 WHERE table_name IN ('PKG_CRYPTO_CORE', 'PKG_CRYPTO_FMT', 'PKG_CRYPTO_POLICY',
                      'PKG_PROVIDER_DBMS', 'PKG_KEY_STORE', 'PKG_AUTHZ')
   AND privilege = 'EXECUTE';

PROMPT
PROMPT === 암호문 테이블과 키 테이블에 대한 직접 권한 점검 (결과가 비어 있어야 정상) ===
SELECT grantee, table_name AS object_name, privilege
  FROM USER_TAB_PRIVS
 WHERE table_name IN ('SEC_KEY', 'SEC_CONFIG', 'SEC_REVEAL_GRANT')
   AND privilege <> 'SELECT';
