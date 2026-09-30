-- 지금 어디에 접속했는가
--
-- 19c 는 멀티테넌트 구조라 컨테이너가 여럿이다. `sqlplus / as sysdba` 로 붙으면
-- 컨테이너 루트(CDB$ROOT)로 들어가는데, 업무 데이터와 계정은 그 안의 PDB 에 있다.
-- 루트에 설치하면 안 되므로, 무엇보다 먼저 어디에 있는지 확인한다.
--
-- 읽기만 하며 아무것도 바꾸지 않는다.

SET SERVEROUTPUT ON SIZE UNLIMITED
SET LINESIZE 200
SET FEEDBACK OFF

PROMPT
PROMPT === 지금 접속한 곳 ===
SELECT SYS_CONTEXT('USERENV', 'SESSION_USER')    AS 접속계정,
       SYS_CONTEXT('USERENV', 'CON_NAME')        AS 컨테이너,
       SYS_CONTEXT('USERENV', 'CON_ID')          AS 컨테이너번호,
       SYS_CONTEXT('USERENV', 'DB_NAME')         AS DB이름
  FROM DUAL;

PROMPT
PROMPT === 이 컨테이너의 문자집합 ===
SELECT parameter, value
  FROM nls_database_parameters
 WHERE parameter IN ('NLS_CHARACTERSET', 'NLS_NCHAR_CHARACTERSET');

PROMPT
PROMPT === 멀티테넌트 여부와 PDB 목록 ===
PROMPT     CDB 가 YES 이고 지금 컨테이너가 CDB$ROOT 라면, 아직 업무 DB 에 있지 않다.
SELECT name AS DB이름, cdb AS 멀티테넌트여부, open_mode AS 상태 FROM v$database;

-- 루트에 있을 때만 PDB 목록이 보인다. PDB 안에서는 자기 자신만 나온다.
SELECT con_id AS 번호, name AS PDB이름, open_mode AS 상태, restricted AS 제한모드
  FROM v$pdbs
 ORDER BY con_id;

PROMPT
PROMPT === 다음에 할 일 ===
PROMPT     위 목록에서 작업 대상 PDB 를 고른 뒤, 두 가지 중 하나로 들어간다.
PROMPT
PROMPT     가. 지금 접속을 유지한 채 컨테이너만 바꾼다
PROMPT           ALTER SESSION SET CONTAINER = <PDB이름>;
PROMPT           SHOW CON_NAME
PROMPT
PROMPT     나. 서비스 이름으로 직접 접속한다 (이쪽이 헷갈릴 일이 적다)
PROMPT           sqlplus sys/<암호>@<호스트>:<포트>/<PDB이름> as sysdba
PROMPT
PROMPT     들어간 뒤 컨테이너가 바뀐 것을 확인하고 001_precheck.sql 을 실행한다.
PROMPT     설치는 반드시 PDB 안에서 한다. CDB$ROOT 에 설치하지 말 것.
PROMPT

SET FEEDBACK ON
