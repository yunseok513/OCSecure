-- 권한 판정
--
-- 소유자 권한으로 실행되는 패키지 안에서는 역할이 비활성화되므로, 오라클 권한
-- 체계에 기대지 않고 자체 대장으로 판정한다. 판정 근거가 테이블에 남아 있어야
-- 누가 무엇을 볼 수 있는지 감사자가 확인할 수 있다는 점에서도 이 편이 낫다.
--
-- 기본은 불허다. 대장에 있는 항목만 허용된다. 전면 허용에서 위험한 것을 빼는
-- 방식은 반드시 누락을 낳는다.

CREATE OR REPLACE PACKAGE PKG_AUTHZ AS
  FUNCTION can_reveal(p_domain_code IN VARCHAR2) RETURN BOOLEAN;
  FUNCTION has_admin (p_privilege   IN VARCHAR2) RETURN BOOLEAN;
  PROCEDURE require_admin(p_privilege IN VARCHAR2);
END PKG_AUTHZ;
/

CREATE OR REPLACE PACKAGE BODY PKG_AUTHZ AS

  FUNCTION can_reveal(p_domain_code IN VARCHAR2) RETURN BOOLEAN IS
    v_cnt PLS_INTEGER;
  BEGIN
    SELECT COUNT(*) INTO v_cnt
      FROM SEC_REVEAL_GRANT g
     WHERE g.domain_code = p_domain_code
       AND (g.expires_at IS NULL OR g.expires_at > SYSTIMESTAMP)
       AND ( (g.grantee_type = 'USER'
              AND g.grantee_name = SYS_CONTEXT('USERENV', 'SESSION_USER'))
          OR (g.grantee_type = 'ROLE'
              AND g.grantee_name IN (SELECT granted_role FROM V_SEC_SESSION_ROLES)) );
    RETURN v_cnt > 0;
  END can_reveal;

  FUNCTION has_admin(p_privilege IN VARCHAR2) RETURN BOOLEAN IS
    v_cnt PLS_INTEGER;
  BEGIN
    SELECT COUNT(*) INTO v_cnt
      FROM SEC_ADMIN_GRANT g
     WHERE g.privilege = p_privilege
       AND (g.expires_at IS NULL OR g.expires_at > SYSTIMESTAMP)
       AND ( (g.grantee_type = 'USER'
              AND g.grantee_name = SYS_CONTEXT('USERENV', 'SESSION_USER'))
          OR (g.grantee_type = 'ROLE'
              AND g.grantee_name IN (SELECT granted_role FROM V_SEC_SESSION_ROLES)) );
    RETURN v_cnt > 0;
  END has_admin;

  PROCEDURE require_admin(p_privilege IN VARCHAR2) IS
  BEGIN
    IF NOT has_admin(p_privilege) THEN
      PKG_AUDIT.log('ADMIN_DENIED', 'ALERT', NULL, '요청 권한: ' || p_privilege);
      PKG_SEC_ERR.raise_err(PKG_SEC_ERR.e_no_reveal, '관리 권한 없음: ' || p_privilege);
    END IF;
  END require_admin;

END PKG_AUTHZ;
/
