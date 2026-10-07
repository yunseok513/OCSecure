-- 예시 객체 정리
-- 800 과 810 을 실행한 업무 계정(응용 스키마)으로 실행한다. 두 파일이 만든 예시 객체만
-- 지운다. 예시 표와 뷰에는 'OCSecure sample' 이라는 표시(COMMENT)가 달려 있고, 표시가
-- 있는 것만 지우므로 같은 이름의 실제 업무 객체는 건드리지 않는다. 없는 것은 건너뛴다.
--
-- 지우는 것: 트리거 TRG_TB_MEMBER_IOD, TRG_TB_STAFF_IOD, 뷰 TB_MEMBER, TB_STAFF,
-- 표 TB_MEMBER_ENC, TB_STAFF_ENC, 프로시저 SP_STAFF_SET_PWD, 함수 FN_STAFF_LOGIN.
-- 뒤의 둘은 810 을 실행한 경우에만 있으며, 810 의 표 TB_STAFF_ENC 에 표시가 있을 때
-- 함께 지운다.

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

  FUNCTION marked(p_table IN VARCHAR2) RETURN BOOLEAN IS
    v_c VARCHAR2(4000);
  BEGIN
    SELECT comments INTO v_c FROM user_tab_comments WHERE table_name = p_table;
    RETURN v_c = 'OCSecure sample';
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      RETURN FALSE;
  END marked;
BEGIN
  IF SYS_CONTEXT('USERENV', 'SESSION_USER') IN
       ('OCS_OWNER', 'OCS_KEYADM', 'OCS_AUDITOR', 'SYS', 'SYSTEM') THEN
    DBMS_OUTPUT.PUT_LINE('예시를 만든 업무 계정으로 접속하여 실행하십시오. 아무것도 지우지 않았다.');
    RETURN;
  END IF;

  IF marked('TB_MEMBER_ENC') THEN
    d('DROP TRIGGER TRG_TB_MEMBER_IOD');
    d('DROP VIEW TB_MEMBER');
    d('DROP TABLE TB_MEMBER_ENC PURGE');
  ELSE
    DBMS_OUTPUT.PUT_LINE('  TB_MEMBER_ENC: 표시가 있는 예시 표가 없어 건너뜀');
  END IF;

  IF marked('TB_STAFF_ENC') THEN
    d('DROP TRIGGER TRG_TB_STAFF_IOD');
    d('DROP VIEW TB_STAFF');
    d('DROP TABLE TB_STAFF_ENC PURGE');
    d('DROP PROCEDURE SP_STAFF_SET_PWD');
    d('DROP FUNCTION FN_STAFF_LOGIN');
  ELSE
    DBMS_OUTPUT.PUT_LINE('  TB_STAFF_ENC: 표시가 있는 예시 표가 없어 건너뜀');
  END IF;
END;
/

PROMPT
PROMPT 남은 예시 표 (표시가 달린 것이 없어야 한다)
SELECT table_name FROM user_tab_comments WHERE comments = 'OCSecure sample' ORDER BY 1;
