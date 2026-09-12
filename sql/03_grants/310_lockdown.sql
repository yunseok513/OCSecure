-- 운영 전환 잠금
-- 설치와 자체 시험을 마친 뒤 SYS 또는 그에 준하는 권한으로 실행한다.
--
-- 이 단계를 건너뛰면 앞의 모든 통제가 무의미해진다. 암호 모듈 소유 계정으로
-- 누구든 접속할 수 있으면 패키지를 바꾸는 것도 키를 꺼내는 것도 가능하기 때문이다.

-- 1. 암호 모듈 소유 계정 잠금 ---------------------------------------------------
-- 배포 작업이 필요할 때만 승인 절차를 거쳐 일시적으로 해제한다.
-- 해제와 재잠금 사실은 통합 감사로 남는다.
ALTER USER OCS_OWNER ACCOUNT LOCK;

-- 2. 운영 설정으로 전환 ----------------------------------------------------------
-- 개발 전용 설정이 운영에 남아 있으면 통제가 사실상 없는 것과 같다.
-- 아래 두 값은 반드시 확인할 것.
--   KEK_SOURCE  = EXTERNAL   (GLOBAL_CTX 는 개발 전용)
--   APPCTX_MODE = PROOF      (SIMPLE 은 개발 전용)
PROMPT
PROMPT === 운영 전환 설정 점검 ===
SELECT cfg_key, cfg_value,
       CASE WHEN cfg_key = 'KEK_SOURCE'  AND cfg_value <> 'EXTERNAL' THEN '위험'
            WHEN cfg_key = 'APPCTX_MODE' AND cfg_value <> 'PROOF'    THEN '위험'
            ELSE '정상' END AS verdict
  FROM OCS_OWNER.SEC_CONFIG
 WHERE cfg_key IN ('KEK_SOURCE', 'APPCTX_MODE');

-- 3. 감사 정책 ------------------------------------------------------------------
-- 보안관리 설계서 제9절에서 반드시 감사하도록 정한 다섯 가지 사건이다.
-- 통합 감사(12c 이상)를 전제로 한다.

CREATE AUDIT POLICY ocs_pol_owner_access
  ACTIONS LOGON, LOGOFF
  WHEN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') = ''OCS_OWNER'''
  EVALUATE PER SESSION;

CREATE AUDIT POLICY ocs_pol_ddl
  ACTIONS CREATE PROCEDURE, ALTER PROCEDURE, DROP PROCEDURE,
          CREATE TABLE, ALTER TABLE, DROP TABLE,
          CREATE TRIGGER, ALTER TRIGGER, DROP TRIGGER,
          CREATE VIEW, DROP VIEW;

CREATE AUDIT POLICY ocs_pol_key_table
  ACTIONS SELECT ON OCS_OWNER.SEC_KEY,
          INSERT ON OCS_OWNER.SEC_KEY,
          UPDATE ON OCS_OWNER.SEC_KEY,
          DELETE ON OCS_OWNER.SEC_KEY,
          SELECT ON OCS_OWNER.SEC_CONFIG,
          UPDATE ON OCS_OWNER.SEC_CONFIG;

CREATE AUDIT POLICY ocs_pol_priv_change
  PRIVILEGES GRANT ANY OBJECT PRIVILEGE, GRANT ANY PRIVILEGE, GRANT ANY ROLE;

AUDIT POLICY ocs_pol_owner_access;
AUDIT POLICY ocs_pol_ddl;
AUDIT POLICY ocs_pol_key_table;
AUDIT POLICY ocs_pol_priv_change;

-- 4. 남은 일 --------------------------------------------------------------------
-- 아래는 데이터베이스 밖에서 해야 하는 일이며, 이 스크립트로는 처리되지 않는다.
-- 하지 않으면 감사 기록을 감사 대상이 지울 수 있으므로 통제가 성립하지 않는다.
--
--   가. UNIFIED_AUDIT_TRAIL 을 외부 보안 관제로 즉시 전송하도록 구성한다.
--   나. 응용 계정의 접속 지점을 sqlnet.ora 의 노드 검증으로 제한한다.
--   다. 패키지 소스의 해시를 추출하여 데이터베이스 밖에 보관하고 정기 대조한다.
--   라. 마스터 키 백업본의 복구 시험을 수행하고 결과를 기록한다.
PROMPT
PROMPT === 잠금 완료. 위 4항의 데이터베이스 외부 조치가 남아 있다. ===
