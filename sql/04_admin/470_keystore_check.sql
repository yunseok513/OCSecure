-- 키 저장소 상태 점검
-- OCS_KEYADM 계정으로 실행한다. 아무것도 바꾸지 않는다.
--
-- 한 줄로 세 가지를 보여 준다.
--   세션        이 창의 세션 번호. 창을 구별하는 데 쓴다.
--   전역 문맥   마스터 키가 인스턴스 전체의 문맥에 들어 있는가. 키 값은 보이지 않는다.
--   저장소      이 세션이 키를 쓸 수 있다고 보는가.
--
-- 두 값이 다를 수 있다. 저장소는 세션이 담아 둔 값을 보기 때문에, 다른 세션이
-- 저장소를 닫아 전역 문맥이 비워진 뒤에도 이미 키를 올려 둔 세션에는 열림으로 보일
-- 수 있다. 이 스크립트가 그 차이를 확인하는 데 쓰인다.
--
-- 주의. 전역 문맥에 키가 있으면 이 스크립트를 실행하는 것만으로 이 세션이 키를
-- 올려 둔 상태가 된다.

SET SERVEROUTPUT ON
SET FEEDBACK OFF

DECLARE
  v_ctx  VARCHAR2(10);
  v_open VARCHAR2(10);
BEGIN
  -- SCOPED_CTX 의 문맥은 토큰 없이는 읽히므로 패키지 함수로 묻는다.
  v_ctx  := CASE WHEN OCS_OWNER.PKG_KEK_PROVIDER.context_present = 1
                 THEN '있음' ELSE '없음' END;
  v_open := CASE WHEN OCS_OWNER.PKG_KEK_PROVIDER.is_open
                 THEN '열림' ELSE '닫힘' END;
  DBMS_OUTPUT.PUT_LINE('세션 ' || SYS_CONTEXT('USERENV', 'SID')
                       || ' : 전역 문맥 ' || v_ctx
                       || ' / 저장소 ' || v_open);
END;
/

SET FEEDBACK ON
