-- OCSecure 계정과 역할 생성
-- SYS 또는 그에 준하는 권한으로 실행한다.
--
-- 보안관리 설계서 제5절의 네 종 계정 구조를 그대로 옮긴 것이다.
-- 비밀번호는 여기에 두지 않는다. 설치 시 치환 변수로 입력받는다.

SET DEFINE ON
ACCEPT sec_owner_pwd    CHAR PROMPT '암호 모듈 소유 계정(OCS_OWNER) 비밀번호: '   HIDE
ACCEPT key_admin_pwd    CHAR PROMPT '키 관리 계정(OCS_KEYADM) 비밀번호: '        HIDE
ACCEPT auditor_pwd      CHAR PROMPT '감사 계정(OCS_AUDITOR) 비밀번호: '          HIDE
ACCEPT app_user_pwd     CHAR PROMPT '응용 계정(OCS_APP) 비밀번호: '              HIDE

-- 1. 암호 모듈 소유 계정 -----------------------------------------------------
-- 모든 암호 패키지와 키 메타데이터를 소유한다. 평상시 잠금 상태로 둔다.
CREATE USER OCS_OWNER IDENTIFIED BY "&sec_owner_pwd"
  DEFAULT TABLESPACE USERS QUOTA UNLIMITED ON USERS;

GRANT CREATE SESSION, CREATE TABLE, CREATE PROCEDURE, CREATE SEQUENCE,
      CREATE VIEW, CREATE TRIGGER, CREATE ANY CONTEXT TO OCS_OWNER;
-- 아래 세 건은 SYS 가 부여해야 한다. 일반 DBA 계정으로는 ORA-01031 이 날 수
-- 있고, SQL*Plus 는 오류가 나도 다음 문장으로 넘어가므로 화면을 지나쳐 버리기
-- 쉽다. 이 파일 끝의 점검 조회로 세 건이 모두 들어갔는지 반드시 확인할 것.
GRANT EXECUTE ON SYS.DBMS_CRYPTO TO OCS_OWNER;
GRANT EXECUTE ON SYS.DBMS_LOCK   TO OCS_OWNER;  -- 복호화 실패 시 지연에 사용
-- 소유자 권한 패키지 안에서는 역할이 비활성이므로, 역할 소속을 사전에서 직접 읽는다.
-- 뷰 V_SEC_SESSION_ROLES 가 이것을 쓰므로, 없으면 030_views.sql 이 실패한다.
GRANT SELECT  ON SYS.DBA_ROLE_PRIVS TO OCS_OWNER;

-- 2. 키 관리 계정 -----------------------------------------------------------
-- 키를 생성하고 교체한다. 데이터 테이블에는 어떤 권한도 갖지 않는다.
CREATE USER OCS_KEYADM IDENTIFIED BY "&key_admin_pwd";
GRANT CREATE SESSION TO OCS_KEYADM;

-- 3. 감사 계정 --------------------------------------------------------------
-- 감사 로그를 읽기만 한다. 어떤 조작 권한도 갖지 않는다.
CREATE USER OCS_AUDITOR IDENTIFIED BY "&auditor_pwd";
GRANT CREATE SESSION TO OCS_AUDITOR;

-- 4. 응용 계정 --------------------------------------------------------------
-- 애플리케이션이 사용한다. 최상위 인터페이스 패키지만 실행할 수 있다.
CREATE USER OCS_APP IDENTIFIED BY "&app_user_pwd"
  DEFAULT TABLESPACE USERS QUOTA UNLIMITED ON USERS;
GRANT CREATE SESSION TO OCS_APP;

-- 역할 -----------------------------------------------------------------------
-- 권한을 계정에 직접 주지 않고 역할을 거치게 하여, 권한 현황 점검을 쉽게 한다.
CREATE ROLE OCS_ROLE_APP;      -- 암호화/색인 생성 + 정책이 허용하는 범위의 복호화
CREATE ROLE OCS_ROLE_KEYADM;   -- 키 생성/활성/폐기
CREATE ROLE OCS_ROLE_AUDITOR;  -- 감사 로그 조회

GRANT OCS_ROLE_APP     TO OCS_APP;
GRANT OCS_ROLE_KEYADM  TO OCS_KEYADM;
GRANT OCS_ROLE_AUDITOR TO OCS_AUDITOR;

-- 보안 애플리케이션 문맥 ------------------------------------------------------
-- 이 문맥은 지정된 패키지에서만 설정할 수 있다. 응용 계정이 조회 도구로 직접
-- 접속한 경우에는 문맥이 비어 있으므로 정책 계층이 복호화를 거부한다.
CREATE OR REPLACE CONTEXT OCS_APP_CTX USING OCS_OWNER.PKG_APP_CONTEXT;

-- 마스터 키 주입용 전역 문맥. KEK_SOURCE=GLOBAL_CTX 인 개발/시험 환경에서만 쓴다.
-- 전역 문맥은 네임스페이스를 아는 세션이면 값을 읽을 수 있으므로, 운영계에서는
-- KEK_SOURCE 를 EXTERNAL 로 두고 이 문맥을 사용하지 않는다.
CREATE OR REPLACE CONTEXT OCS_KEK_CTX USING OCS_OWNER.PKG_KEK_PROVIDER ACCESSED GLOBALLY;

-- 소유 계정 잠금은 설치와 자체 시험을 마친 뒤 03_grants/310_lockdown.sql 에서 수행한다.

SET DEFINE OFF

-- 점검 -----------------------------------------------------------------------
-- 아래 세 조회는 모두 결과가 비어 있어야 한다. 한 건이라도 나오면 그 항목이
-- 빠진 것이므로, SYS 로 접속하여 해당 구문을 다시 부여한 뒤 진행해야 한다.

PROMPT === 빠진 SYS 객체 권한 (없어야 정상) ===
SELECT 'GRANT ' || r.priv || ' ON SYS.' || r.obj || ' TO OCS_OWNER;' AS 다시_부여할_구문
  FROM (SELECT 'DBMS_CRYPTO'    AS obj, 'EXECUTE' AS priv FROM dual
        UNION ALL SELECT 'DBMS_LOCK',      'EXECUTE' FROM dual
        UNION ALL SELECT 'DBA_ROLE_PRIVS', 'SELECT'  FROM dual) r
 WHERE NOT EXISTS (SELECT 1 FROM dba_tab_privs p
                    WHERE p.grantee = 'OCS_OWNER' AND p.owner = 'SYS'
                      AND p.table_name = r.obj AND p.privilege = r.priv);

PROMPT === 빠진 계정 (없어야 정상) ===
SELECT r.u AS 없는_계정
  FROM (SELECT 'OCS_OWNER' AS u FROM dual
        UNION ALL SELECT 'OCS_KEYADM' FROM dual
        UNION ALL SELECT 'OCS_AUDITOR' FROM dual
        UNION ALL SELECT 'OCS_APP' FROM dual) r
 WHERE NOT EXISTS (SELECT 1 FROM dba_users u WHERE u.username = r.u);

PROMPT === 빠진 역할과 문맥 (없어야 정상) ===
SELECT r.n AS 없는_역할
  FROM (SELECT 'OCS_ROLE_APP' AS n FROM dual
        UNION ALL SELECT 'OCS_ROLE_KEYADM' FROM dual
        UNION ALL SELECT 'OCS_ROLE_AUDITOR' FROM dual) r
 WHERE NOT EXISTS (SELECT 1 FROM dba_roles d WHERE d.role = r.n);

SELECT r.n AS 없는_문맥
  FROM (SELECT 'OCS_APP_CTX' AS n FROM dual
        UNION ALL SELECT 'OCS_KEK_CTX' FROM dual) r
 WHERE NOT EXISTS (SELECT 1 FROM dba_context c WHERE c.namespace = r.n);
