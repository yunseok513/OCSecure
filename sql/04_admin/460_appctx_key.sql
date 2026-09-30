-- 애플리케이션 인증 문맥용 키 등록
-- OCS_KEYADM 계정으로 실행한다. 실행 전에 마스터 키가 주입되어 있어야 한다.
--
-- 이 키는 애플리케이션 계층이 증표를 계산할 때 쓰는 비밀이다. 응용 계정의 접속
-- 정보를 알아낸 사람이 조회 도구로 직접 붙더라도, 이 키가 없으면 증표를 만들 수
-- 없어 문맥이 서지 않고 따라서 복호화도 되지 않는다. 데이터베이스 접속 정보만
-- 으로는 뚫리지 않게 하는 장치다.
--
-- 그러므로 이 키는 데이터베이스 밖에서 만들어 들여온다. 데이터베이스 안에서
-- 난수로 만들면 애플리케이션에 줄 방법이 없고, 데이터베이스 관리자가 값을 보게
-- 되어 장치의 취지가 무너진다.
--
-- 값은 이렇게 만든다. 애플리케이션 담당자가 만들어 전달하는 것이 가장 낫다.
--
--   python -c "import secrets; print('\n'.join(secrets.token_hex(32) for _ in range(3)))"
--
-- 세 줄이 나온다. 첫째와 둘째는 이 도메인에서 쓰이지 않으며 규격을 맞추기 위한
-- 것이다. 셋째가 실제 증표 계산에 쓰이는 값이며, 이것을 애플리케이션 서버 설정에
-- 넣는다. 데이터베이스 쪽에는 감싸인 형태로만 남는다.

SET SERVEROUTPUT ON SIZE 100000
SET FEEDBACK OFF
SET DEFINE ON

ACCEPT k_enc CHAR PROMPT '  1) 예비 키 1 (16진 64자): '
ACCEPT k_mac CHAR PROMPT '  2) 예비 키 2 (16진 64자): '
ACCEPT k_idx CHAR PROMPT '  3) 증표용 키  (16진 64자): '

PROMPT
PROMPT === 1. 도메인 등록 ===
BEGIN
  -- 자료 도메인이 아니라 내부용이다. 문맥을 세우는 데 쓰는 것이므로
  -- 스스로 문맥을 요구하면 안 된다.
  OCS_OWNER.PKG_KEY_ADMIN.upsert_domain(
    '_APPCTX', '애플리케이션 인증 문맥 증표용', 'NONE', 'ALL', 'N', 0, 'NONE');
  COMMIT;
  DBMS_OUTPUT.PUT_LINE('  _APPCTX 도메인 등록 완료');
END;
/

PROMPT
PROMPT === 2. 키 등록 ===
DECLARE
  v_id  PLS_INTEGER;
  v_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_cnt FROM OCS_OWNER.V_SEC_KEY_STATUS
   WHERE domain_code = '_APPCTX' AND key_state = 'ACTIVE';
  IF v_cnt > 0 THEN
    DBMS_OUTPUT.PUT_LINE('  활성 키가 이미 있다. 새로 만들지 않는다.');
    DBMS_OUTPUT.PUT_LINE('  바꾸려면 기존 키를 폐기한 뒤 다시 실행할 것.');
    RETURN;
  END IF;

  v_id := OCS_OWNER.PKG_KEY_ADMIN.import_key(
            '_APPCTX',
            HEXTORAW('&k_enc'), HEXTORAW('&k_mac'), HEXTORAW('&k_idx'),
            NULL, TRUE, '애플리케이션 증표용 초기 키');
  COMMIT;
  DBMS_OUTPUT.PUT_LINE('  등록 완료. key_id = ' || v_id);
END;
/

SET DEFINE OFF

PROMPT
PROMPT === 3. 확인 ===
SELECT domain_code, key_id, key_state FROM OCS_OWNER.V_SEC_KEY_STATUS
 WHERE domain_code = '_APPCTX';

PROMPT
PROMPT 세 번째로 넣은 증표용 키를 애플리케이션 서버 설정에 넣을 것.
PROMPT 데이터베이스 쪽에서는 이 값을 다시 꺼낼 수 없다.

SET FEEDBACK ON
