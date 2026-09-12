-- 보조 뷰
-- OCS_OWNER 계정으로 실행한다.

-- 현재 세션 사용자가 직접 또는 간접으로 보유한 역할 목록.
--
-- 소유자 권한으로 실행되는 PL/SQL 안에서는 역할이 비활성화되므로 SESSION_ROLES
-- 로는 판정할 수 없다. 사전에서 직접 풀어야 한다. 중첩 역할까지 따라가되
-- 순환이 있어도 멈추도록 NOCYCLE 을 둔다.
CREATE OR REPLACE VIEW V_SEC_SESSION_ROLES AS
SELECT DISTINCT granted_role
  FROM SYS.DBA_ROLE_PRIVS
 START WITH grantee = SYS_CONTEXT('USERENV', 'SESSION_USER')
 CONNECT BY NOCYCLE PRIOR granted_role = grantee;

-- 현재 유효한 복호화 허용 내역. 만료된 한시 권한은 자동으로 빠진다.
CREATE OR REPLACE VIEW V_SEC_EFFECTIVE_REVEAL AS
SELECT g.domain_code, g.grantee_type, g.grantee_name, g.expires_at, g.reason
  FROM SEC_REVEAL_GRANT g
 WHERE g.expires_at IS NULL OR g.expires_at > SYSTIMESTAMP;

-- 키 현황. 감사자가 교체 이력을 확인하는 데 쓴다. 키 값은 나오지 않는다.
CREATE OR REPLACE VIEW V_SEC_KEY_STATUS AS
SELECT k.key_id, k.domain_code, k.alg_id, k.key_state,
       k.created_at, k.created_by, k.activated_at, k.retired_at, k.note
  FROM SEC_KEY k;
