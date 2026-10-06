-- 예시 객체 정리
-- OCS_APP 계정으로 실행한다. 800 과 810 이 만든 예시 객체를 지운다. 없는 객체는
-- 건너뛴다. 실제 업무 객체는 이름이 다르므로 건드리지 않는다.
--
-- 지우는 것: 트리거 TRG_TB_MEMBER_IOD, TRG_TB_STAFF_IOD, 뷰 TB_MEMBER, TB_STAFF,
-- 표 TB_MEMBER_ENC, TB_STAFF_ENC, 프로시저 SP_STAFF_SET_PWD, 함수 FN_STAFF_LOGIN.

SET SERVEROUTPUT ON

DECLARE
  PROCEDURE d(p_sql IN VARCHAR2) IS
  BEGIN
    EXECUTE IMMEDIATE p_sql;
    DBMS_OUTPUT.PUT_LINE('  지움: ' || p_sql);
  EXCEPTION
    WHEN OTHERS THEN
      -- 942 표나 뷰 없음, 4080 트리거 없음, 4043 객체 없음
      IF SQLCODE NOT IN (-942, -4080, -4043) THEN
        DBMS_OUTPUT.PUT_LINE('  [실패] ' || p_sql || ' : ' || SQLERRM);
      END IF;
  END d;
BEGIN
  IF SYS_CONTEXT('USERENV', 'SESSION_USER') <> 'OCS_APP' THEN
    DBMS_OUTPUT.PUT_LINE('OCS_APP 으로 접속하여 실행하십시오. 아무것도 지우지 않았다.');
    RETURN;
  END IF;
  d('DROP TRIGGER TRG_TB_MEMBER_IOD');
  d('DROP TRIGGER TRG_TB_STAFF_IOD');
  d('DROP VIEW TB_MEMBER');
  d('DROP VIEW TB_STAFF');
  d('DROP TABLE TB_MEMBER_ENC PURGE');
  d('DROP TABLE TB_STAFF_ENC PURGE');
  d('DROP PROCEDURE SP_STAFF_SET_PWD');
  d('DROP FUNCTION FN_STAFF_LOGIN');
END;
/

PROMPT
PROMPT 남은 예시 객체 (없어야 한다)
SELECT object_name, object_type FROM user_objects
 WHERE object_name IN ('TB_MEMBER_ENC', 'TB_MEMBER', 'TRG_TB_MEMBER_IOD',
                       'TB_STAFF_ENC', 'TB_STAFF', 'TRG_TB_STAFF_IOD',
                       'SP_STAFF_SET_PWD', 'FN_STAFF_LOGIN')
 ORDER BY 1;
