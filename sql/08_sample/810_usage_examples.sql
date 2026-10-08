-- 암호화 적용 예시 모음
-- 업무 계정(응용 스키마)으로 실행한다.
--
-- 이 파일은 셋을 한자리에서 보이려고 만들었다.
--   제1장  암호화 테이블과 투명화 뷰와 트리거를 만드는 예시
--   제2장  단방향(비밀번호 해시, 검색용 색인)을 쓰는 예시
--   제3장  양방향(암호화와 복호화와 마스킹)을 쓰는 예시
--
-- 800_sample_member.sql 과는 별개의 표를 쓰므로 둘을 함께 두어도 부딪히지 않는다.
-- 저쪽이 최소 구성이라면 이쪽은 비밀번호까지 포함한 완전한 모양이다.
--
-- 전제가 셋 있다. 마스터 키가 주입되어 있어야 하고, 도메인과 운영 키가 등록되어
-- 있어야 하며(설치 매뉴얼의 마스터 키 절과 도메인과 키 절. 윈도우 개발·시험은 제3.8절과 제3.9절), 응용 계정에 표와 뷰와 트리거와 프로시저를
-- 만들 권한이 있어야 한다.
--
--   GRANT CREATE TABLE, CREATE VIEW, CREATE TRIGGER, CREATE PROCEDURE TO <응용 스키마>;
--
-- 어디까지 조회 도구로 돌려 볼 수 있는지 미리 밝혀 둔다.
--
--   제1장        돈다. 표와 뷰를 만들 뿐 암복호화를 하지 않는다.
--   제2.1~2.2절  돈다. 비밀번호 해시는 소금과 반복 횟수만 쓰므로 마스터 키도
--                애플리케이션 인증 문맥도 필요하지 않다. 설정과 검증을 지금
--                바로 쳐 보실 수 있다.
--   제2.3절      돌지 않는다. 검색용 색인은 운영 키로 계산하므로 문맥이 필요하다.
--   제3장        돌지 않는다. 암복호화 전부가 문맥을 요구한다.
--
-- 돌지 않는 구문을 조회 도구에서 그대로 치면 ORA-20521 로 거부된다. 그것이 정상
-- 동작이다. 응용 코드에서 쓰는 본보기로 읽으시고, 실제로 돌려 보시려면 연동 확인
-- 프로그램을 쓰신다.


-- ===========================================================================
-- 제1장  테이블과 뷰 만들기
-- ===========================================================================

-- 1.1 실제 저장 테이블 -------------------------------------------------------
--
-- 컬럼을 셋으로 나누어 본다.
--
--   평문 그대로 두는 것   : 식별자와 날짜처럼 그 자체로 개인정보가 아닌 것
--   암호문과 색인을 두는 것 : 되돌려 보아야 하고 찾기도 해야 하는 것
--   해시만 두는 것        : 되돌릴 일이 없는 것. 비밀번호가 여기에 든다
--
-- 암호문 컬럼의 길이는 평문 길이에 따라 정한다. 고정 52바이트에 16바이트 블록
-- 단위의 본문이 붙으므로 길이는 52 + 16 * (평문 바이트 수 / 16 의 몫 + 1) 이다.
-- 13자 주민등록번호는 68바이트, 한글 성명 열 자(30바이트)도 84바이트다.
-- RAW(256) 이면 평문 191바이트까지 담으므로 넉넉하다.

CREATE TABLE TB_STAFF_ENC (
  staff_id      NUMBER        NOT NULL,   -- 기본 키. 숫자 단일 키여야 재암호화 배치를 쓸 수 있다
  login_id      VARCHAR2(30)  NOT NULL,   -- 평문. 로그인 식별자라 암호화하지 않는다
  staff_nm_enc  RAW(256),                 -- 성명 암호문
  staff_nm_idx  RAW(32),                  -- 성명 검색용 색인
  rrn_enc       RAW(256),                 -- 주민등록번호 암호문
  rrn_idx       RAW(32),                  -- 주민등록번호 검색용 색인
  tel_enc       RAW(256),                 -- 연락처 암호문. 찾을 일이 없어 색인을 두지 않았다
  pwd_hash      RAW(64),                  -- 비밀번호 저장값. 일방향이라 되돌릴 수 없다
  upd_dt        DATE DEFAULT SYSDATE,
  CONSTRAINT pk_tb_staff_enc PRIMARY KEY (staff_id)
);
COMMENT ON TABLE TB_STAFF_ENC IS 'OCSecure sample';

-- 인덱스는 색인 컬럼과 평문 컬럼에만 만든다. 암호문 컬럼에 만들어도 쓰이지 않는다.
-- 같은 평문이 매번 다른 암호문이 되므로 비교가 성립하지 않기 때문이다.
CREATE UNIQUE INDEX ux_tb_staff_login ON TB_STAFF_ENC (login_id);
CREATE UNIQUE INDEX ux_tb_staff_rrn   ON TB_STAFF_ENC (rrn_idx);
CREATE        INDEX ix_tb_staff_nm    ON TB_STAFF_ENC (staff_nm_idx);

COMMENT ON TABLE  TB_STAFF_ENC          IS '직원 (암호화 저장)';
COMMENT ON COLUMN TB_STAFF_ENC.rrn_idx  IS '주민등록번호 검색용 색인. 열쇠를 넣은 해시라 되돌릴 수 없다';
COMMENT ON COLUMN TB_STAFF_ENC.pwd_hash IS '비밀번호 저장값. PBKDF2-HMAC-SHA256';


-- 1.2 투명화 뷰 ---------------------------------------------------------------
--
-- 응용은 예전 이름 그대로 TB_STAFF 를 쓴다.
--
--   show   : 복호화 자격이 있으면 평문을, 없으면 마스킹된 값을 돌려준다
--   masked : 자격과 무관하게 언제나 가려진 값을 돌려준다. 목록 화면용이다
--
-- 비밀번호 저장값은 뷰에 올리지 않는다. 되돌릴 수 없는 값이라 해도 밖으로 흘리면
-- 공격자가 자기 장비에서 마음껏 대입해 볼 수 있기 때문이다. 대신 설정되어 있는지
-- 여부만 Y/N 으로 보이고, 맞추어 보는 일은 제2장의 함수가 데이터베이스 안에서 한다.

CREATE OR REPLACE VIEW TB_STAFF AS
SELECT staff_id,
       login_id,
       OCS_OWNER.PKG_SECURE_API.show  ('NAME',  staff_nm_enc) AS staff_nm,
       OCS_OWNER.PKG_SECURE_API.show  ('RRN',   rrn_enc)      AS rrn,
       OCS_OWNER.PKG_SECURE_API.show  ('PHONE', tel_enc)      AS tel,
       OCS_OWNER.PKG_SECURE_API.masked('NAME',  staff_nm_enc) AS staff_nm_masked,
       OCS_OWNER.PKG_SECURE_API.masked('RRN',   rrn_enc)      AS rrn_masked,
       CASE WHEN pwd_hash IS NULL THEN 'N' ELSE 'Y' END       AS pwd_set,
       staff_nm_idx,
       rrn_idx,
       upd_dt
  FROM TB_STAFF_ENC;
COMMENT ON TABLE TB_STAFF IS 'OCSecure sample';


-- 1.3 삽입과 수정과 삭제 트리거 -------------------------------------------------
--
-- 응용은 평문을 넣고 트리거가 암호화와 색인 생성을 대신한다.
--
-- 지켜야 할 것이 둘 있다.
--
--   첫째, 뷰에 보이는 컬럼은 하나도 빠짐없이 다룬다. 빠진 컬럼은 갱신이 조용히
--         사라진다. 오류도 나지 않고 한 행 갱신되었다고 나오므로 찾기 어렵다.
--         읽기 전용으로 둘 컬럼(마스킹 컬럼, 색인 컬럼, pwd_set)은 일부러 빼되
--         그렇게 했다는 것을 여기 주석으로 남긴다.
--
--   둘째, 바뀐 컬럼만 다시 암호화한다. :NEW 는 건드리지 않은 컬럼의 현재 값도
--         담고 있어서, 조건 없이 전부 다시 암호화하면 값이 같은데도 초기화 벡터가
--         새로 생겨 암호문이 바뀐다. 쓸데없는 연산과 재실행 로그가 쌓인다.

CREATE OR REPLACE TRIGGER TRG_TB_STAFF_IOD
INSTEAD OF INSERT OR UPDATE OR DELETE ON TB_STAFF
FOR EACH ROW
BEGIN
  IF INSERTING THEN
    INSERT INTO TB_STAFF_ENC (staff_id, login_id,
                              staff_nm_enc, staff_nm_idx,
                              rrn_enc, rrn_idx, tel_enc, upd_dt)
    VALUES (:NEW.staff_id,
            :NEW.login_id,
            OCS_OWNER.PKG_SECURE_API.enc_name(:NEW.staff_nm),
            OCS_OWNER.PKG_SECURE_API.idx_name(:NEW.staff_nm),
            OCS_OWNER.PKG_SECURE_API.enc_rrn (:NEW.rrn),
            OCS_OWNER.PKG_SECURE_API.idx_rrn (:NEW.rrn),
            OCS_OWNER.PKG_SECURE_API.protect ('PHONE', :NEW.tel),
            NVL(:NEW.upd_dt, SYSDATE));
    -- 비밀번호는 여기서 받지 않는다. 가입 직후 SP_STAFF_SET_PWD 로 따로 넣는다.

  ELSIF UPDATING THEN
    -- UPDATING('컬럼명') 은 PL/SQL 조건식에서만 쓸 수 있다. UPDATE 구문 안의
    -- CASE 에 넣으면 PLS-00231 로 컴파일되지 않으므로 컬럼별로 IF 를 가른다.
    UPDATE TB_STAFF_ENC
       SET login_id = :NEW.login_id,
           upd_dt   = :NEW.upd_dt
     WHERE staff_id = :OLD.staff_id;

    IF UPDATING('STAFF_NM') THEN
      UPDATE TB_STAFF_ENC
         SET staff_nm_enc = OCS_OWNER.PKG_SECURE_API.enc_name(:NEW.staff_nm),
             staff_nm_idx = OCS_OWNER.PKG_SECURE_API.idx_name(:NEW.staff_nm)
       WHERE staff_id = :OLD.staff_id;
    END IF;

    IF UPDATING('RRN') THEN
      UPDATE TB_STAFF_ENC
         SET rrn_enc = OCS_OWNER.PKG_SECURE_API.enc_rrn(:NEW.rrn),
             rrn_idx = OCS_OWNER.PKG_SECURE_API.idx_rrn(:NEW.rrn)
       WHERE staff_id = :OLD.staff_id;
    END IF;

    IF UPDATING('TEL') THEN
      UPDATE TB_STAFF_ENC
         SET tel_enc = OCS_OWNER.PKG_SECURE_API.protect('PHONE', :NEW.tel)
       WHERE staff_id = :OLD.staff_id;
    END IF;

  ELSIF DELETING THEN
    DELETE FROM TB_STAFF_ENC WHERE staff_id = :OLD.staff_id;
  END IF;
END;
/


-- ===========================================================================
-- 제2장  단방향 활용 예시
-- ===========================================================================
--
-- 단방향에는 성격이 다른 둘이 있다.
--
--   비밀번호 저장값 : 맞는지만 보면 되고 되돌릴 일이 없다
--   검색용 색인     : 되돌릴 수는 없되 같은 평문에는 늘 같은 값이 나와야 찾을 수 있다
--
-- 둘을 섞으면 안 된다. 비밀번호 저장값은 소금이 섞여 매번 다른 값이 나오므로
-- 검색에 쓸 수 없고, 색인은 매번 같은 값이 나오므로 비밀번호에 쓰면 안 된다.
--
-- 쓰는 키도 다르다. 비밀번호 저장값은 키를 쓰지 않고 소금과 반복 횟수만으로
-- 만들며, 색인은 도메인의 운영 키를 쓴다. 그래서 비밀번호 쪽은 마스터 키가 닫혀
-- 있어도 돌고 색인 쪽은 돌지 않는다. 키를 잃어도 비밀번호 검증은 살아 있다는
-- 뜻이기도 하다.


-- 2.1 비밀번호 설정 ------------------------------------------------------------
--
-- 저장값을 밖으로 내보내지 않으려고 프로시저로 감쌌다. 응용은 평문 비밀번호만
-- 넘기고 해시 값은 보지 못한다.

CREATE OR REPLACE PROCEDURE SP_STAFF_SET_PWD(p_login_id IN VARCHAR2,
                                             p_password IN VARCHAR2) IS
BEGIN
  UPDATE TB_STAFF_ENC
     SET pwd_hash = OCS_OWNER.PKG_SECURE_API.make_pwd(p_password),
         upd_dt   = SYSDATE
   WHERE login_id = p_login_id;

  IF SQL%ROWCOUNT = 0 THEN
    RAISE_APPLICATION_ERROR(-20901, '그런 직원이 없다: ' || p_login_id);
  END IF;
END SP_STAFF_SET_PWD;
/


-- 2.2 로그인 검증 --------------------------------------------------------------
--
-- 돌려주는 값의 뜻
--   0 : 불일치
--   1 : 일치
--   2 : 비밀번호가 설정되어 있지 않다. 설정 화면으로 보낸다
--   3 : 일치하되 반복 횟수가 지금 기준보다 낮다. 통과시키되 다시 저장해 둔다
--
-- 2 를 0 과 구분하는 것이 중요하다. 단일 인증으로 들어오는 이용자는
-- 비밀번호를 쓴 적이 없어 저장값이 비어 있는데, 이것을 로그인 실패로 다루면
-- 안내 문구를 제대로 낼 수 없다.
--
-- 없는 아이디와 틀린 비밀번호를 같은 0 으로 돌려주는 것도 일부러다. 둘을 나누어
-- 알려 주면 어떤 아이디가 실재하는지를 밖에서 헤아릴 수 있게 된다.

CREATE OR REPLACE FUNCTION FN_STAFF_LOGIN(p_login_id IN VARCHAR2,
                                          p_password IN VARCHAR2) RETURN NUMBER IS
  v_hash RAW(64);
BEGIN
  SELECT pwd_hash INTO v_hash FROM TB_STAFF_ENC WHERE login_id = p_login_id;

  IF v_hash IS NULL THEN
    RETURN 2;
  END IF;

  IF OCS_OWNER.PKG_SECURE_API.verify_pwd(p_password, v_hash) = 0 THEN
    RETURN 0;
  END IF;

  IF OCS_OWNER.PKG_SECURE_API.pwd_stale(v_hash) = 1 THEN
    RETURN 3;
  END IF;

  RETURN 1;
EXCEPTION
  WHEN NO_DATA_FOUND THEN
    RETURN 0;
END FN_STAFF_LOGIN;
/

-- 쓰는 모습
--
--   BEGIN SP_STAFF_SET_PWD('hong', '처음정한비밀번호!'); COMMIT; END;
--   /
--   SELECT FN_STAFF_LOGIN('hong', '처음정한비밀번호!') AS r FROM DUAL;   -->  1
--   SELECT FN_STAFF_LOGIN('hong', '틀린값')            AS r FROM DUAL;   -->  0
--   SELECT FN_STAFF_LOGIN('없는아이디', '아무거나')     AS r FROM DUAL;   -->  0
--
-- 3 이 나오면 설정의 반복 횟수를 올린 뒤라는 뜻이다. 로그인은 시키되 같은 자리에서
-- 다시 저장해 두면 다음부터 1 이 나온다.
--
--   IF FN_STAFF_LOGIN(...) = 3 THEN SP_STAFF_SET_PWD(아이디, 방금 받은 비밀번호); END IF;


-- 2.3 검색용 색인 ---------------------------------------------------------------
--
-- 평문을 모르면 색인 값을 만들 수 없고, 색인 값에서 평문을 되돌릴 수도 없다.
-- 그러면서도 같은 평문에는 늘 같은 값이 나오므로 인덱스를 타고 한 건을 찾는다.
--
--   SELECT staff_id, login_id, staff_nm_masked
--     FROM TB_STAFF
--    WHERE rrn_idx = OCS_OWNER.PKG_SECURE_API.idx_rrn('800101-1234567');
--
-- 구분자가 있든 없든 같은 값이 나오므로 아래 둘은 같은 행을 찾는다. 도메인에
-- 정규화 방식을 정해 두었기 때문이다.
--
--   ... idx_rrn('800101-1234567')  =  ... idx_rrn('8001011234567')
--
-- 성명처럼 같은 값이 여럿일 수 있는 컬럼은 유일 인덱스를 두면 안 된다.
--
--   SELECT staff_id, login_id FROM TB_STAFF
--    WHERE staff_nm_idx = OCS_OWNER.PKG_SECURE_API.idx_name('홍길동');
--
-- 이렇게는 쓰지 말 것. 전 행을 복호화한 뒤 비교하므로 인덱스를 타지 못한다.
--
--   SELECT * FROM TB_STAFF WHERE rrn = '800101-1234567';     -- 금지
--
-- 범위 검색과 부분 일치 검색은 색인으로 되지 않는다. 그런 요건이 있다면 업무
-- 협의로 줄이는 편이 낫다. 보조 색인을 늘릴수록 밖으로 드러나는 면도 함께 는다.


-- ===========================================================================
-- 제3장  양방향 활용 예시
-- ===========================================================================
--
-- 아래 구문은 모두 애플리케이션 인증 문맥이 서 있어야 돈다. 응용에서는 접속
-- 직후에 PKG_SECURE_API.login 으로 문맥을 세운다. 마스터 키도 열려 있어야 한다.


-- 3.1 넣기 ----------------------------------------------------------------------
--
-- 응용은 평문을 그대로 넣는다. 암호화와 색인 생성은 트리거가 한다.
--
--   INSERT INTO TB_STAFF (staff_id, login_id, staff_nm, rrn, tel)
--   VALUES (1001, 'hong', '홍길동', '800101-1234567', '010-1234-5678');
--
--   BEGIN SP_STAFF_SET_PWD('hong', '처음정한비밀번호!'); END;
--   /
--   COMMIT;


-- 3.2 꺼내기 ---------------------------------------------------------------------
--
-- 목록 화면은 마스킹 컬럼만 읽는다. 평문 컬럼을 읽으면 돌려주는 행마다 복호화가
-- 일어나 느려지고, 도메인에 둔 사용량 임계치에도 걸린다.
--
--   SELECT staff_id, login_id, staff_nm_masked, rrn_masked, pwd_set
--     FROM TB_STAFF ORDER BY staff_id;
--
-- 상세 화면에서만 평문 컬럼을 읽는다. 복호화 자격이 있으면 평문이, 없으면
-- 마스킹된 값이 나온다. 자격이 없다고 오류가 나지는 않는다.
--
--   SELECT staff_nm, rrn, tel FROM TB_STAFF WHERE staff_id = 1001;
--
-- 지금 세션에 자격이 있는지는 미리 물어볼 수 있다. Y 또는 N 이 나온다.
--
--   SELECT OCS_OWNER.PKG_SECURE_API.allowed('RRN') FROM DUAL;
--
-- 화면에 들어가기 전에 암복호화가 가능한 상태인지도 물어볼 수 있다. 1 이면 가능,
-- 0 이면 키 저장소가 닫혀 있다는 뜻이다. 0 일 때는 오류 추적을 그대로 보이지 말고
-- 안내 화면을 내보낸다.
--
--   SELECT OCS_OWNER.PKG_SECURE_API.ready FROM DUAL;


-- 3.3 고치기와 지우기 --------------------------------------------------------------
--
-- 뷰에 그대로 쓴다. 바뀐 컬럼만 다시 암호화된다.
--
--   UPDATE TB_STAFF SET tel = '010-0000-0000' WHERE staff_id = 1001;
--   UPDATE TB_STAFF SET staff_nm = '홍길순'    WHERE staff_id = 1001;
--   DELETE FROM TB_STAFF WHERE staff_id = 1001;
--   COMMIT;
--
-- 뷰로는 할 수 없는 것들이 있다. 직접 경로 삽입과 SQL*Loader 직접 경로와 병렬
-- DML 은 INSTEAD OF 트리거가 달린 뷰에서 쓰이지 않는다. 대량 이행 작업은 뷰가
-- 아니라 TB_STAFF_ENC 를 상대로 하고, 암호화는 응용에서 미리 해 넣어야 한다.


-- 3.4 암호문을 직접 다루기 ----------------------------------------------------------
--
-- 뷰를 쓰지 않고 응용이 직접 부를 수도 있다. 새로 만드는 화면이라 투명화가 필요
-- 없을 때 쓴다. 이름을 업무 의미로 지어 두었으므로, 나중에 어느 화면이 주민등록번호를
-- 평문으로 쓰는지 조사할 때 이름으로 검색하면 바로 드러난다.
--
--   DECLARE
--     v_cipher RAW(256);
--     v_plain  VARCHAR2(100);
--   BEGIN
--     OCS_OWNER.PKG_SECURE_API.login('화면식별자', :epoch, :proof);
--
--     v_cipher := OCS_OWNER.PKG_SECURE_API.enc_rrn('800101-1234567');
--     v_plain  := OCS_OWNER.PKG_SECURE_API.dec_rrn(v_cipher);        -- 자격이 있어야 한다
--     DBMS_OUTPUT.PUT_LINE(OCS_OWNER.PKG_SECURE_API.mask_rrn(v_cipher));
--
--     OCS_OWNER.PKG_SECURE_API.logout;
--   END;
--   /
--
-- 표준 도메인 밖의 자료는 일반형으로 다룬다. 도메인은 키 관리 계정이 미리 등록해
-- 두어야 하며, 없는 도메인으로는 저장할 수 없다.
--
--   protect('EMAIL', '...') / reveal('EMAIL', ...) / masked('EMAIL', ...)
--   search_of('EMAIL', '...')


-- ===========================================================================
-- 뒷정리
-- ===========================================================================
--
-- 예시를 지우실 때 쓴다. 순서를 지켜야 한다.
--
--   DROP TRIGGER   TRG_TB_STAFF_IOD;
--   DROP VIEW      TB_STAFF;
--   DROP FUNCTION  FN_STAFF_LOGIN;
--   DROP PROCEDURE SP_STAFF_SET_PWD;
--   DROP TABLE     TB_STAFF_ENC PURGE;
