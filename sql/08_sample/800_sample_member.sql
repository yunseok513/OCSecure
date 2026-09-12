-- 투명화 적용 예시
-- OCS_APP 계정으로 실행한다.
--
-- 기존 애플리케이션의 수정 범위를 줄이기 위해, 실제 테이블의 이름을 바꾸고 원래
-- 이름으로 뷰를 만든다. 조회 구문은 손대지 않아도 동작한다.
--
-- 다만 이 방식에는 분명한 한계가 있다. 반드시 함께 읽을 것.
--
--   첫째, 뷰를 통한 조회는 반환되는 모든 행에 대해 복호화를 호출한다. 목록 화면은
--         마스킹 컬럼(mbr_rrn_masked)을 쓰고, 상세 화면에서만 평문 컬럼을 읽도록
--         애플리케이션 쿼리를 정리해야 한다.
--
--   둘째, 암호화 컬럼을 조건절에 쓰던 기존 쿼리는 반드시 고쳐야 한다. 뷰 위에서
--         복호화된 값을 조건으로 걸면 전 행을 복호화한 뒤 비교하게 되어 성능이
--         무너진다. 색인 컬럼을 쓰도록 바꿔야 한다. 예시는 파일 끝에 있다.
--
--   셋째, 뷰는 원본 테이블에 대한 직접 접근을 막지 못한다. 원본에 대한 권한을
--         회수하지 않으면 뷰를 우회할 수 있다.

-- 1. 실제 저장 테이블 ----------------------------------------------------------
CREATE TABLE TB_MEMBER_ENC (
  mbr_id         NUMBER         NOT NULL,
  mbr_name_enc   RAW(256),        -- 성명 암호문
  mbr_name_idx   RAW(32),         -- 성명 검색용 색인
  mbr_rrn_enc    RAW(256),        -- 주민등록번호 암호문
  mbr_rrn_idx    RAW(32),         -- 주민등록번호 검색용 색인
  mbr_phone_enc  RAW(256),
  mbr_pwd        RAW(64),         -- 일방향. 복호화하지 않는다.
  join_dt        DATE DEFAULT SYSDATE,
  CONSTRAINT pk_tb_member_enc PRIMARY KEY (mbr_id)
);

-- 색인 컬럼에만 인덱스를 만든다. 암호문 컬럼은 인덱스를 만들어도 쓸 수 없다.
CREATE UNIQUE INDEX ux_tb_member_rrn ON TB_MEMBER_ENC (mbr_rrn_idx);
CREATE INDEX        ix_tb_member_name ON TB_MEMBER_ENC (mbr_name_idx);

-- 2. 투명화 뷰 -----------------------------------------------------------------
-- 애플리케이션은 예전 이름 그대로 TB_MEMBER 를 쓴다.
-- show 는 자격이 있으면 평문을, 없으면 마스킹된 값을 돌려준다.
CREATE OR REPLACE VIEW TB_MEMBER AS
SELECT mbr_id,
       OCS_OWNER.PKG_SECURE_API.show('NAME',  mbr_name_enc)  AS mbr_name,
       OCS_OWNER.PKG_SECURE_API.show('RRN',   mbr_rrn_enc)   AS mbr_rrn,
       OCS_OWNER.PKG_SECURE_API.show('PHONE', mbr_phone_enc) AS mbr_phone,
       OCS_OWNER.PKG_SECURE_API.masked('RRN', mbr_rrn_enc)   AS mbr_rrn_masked,
       mbr_rrn_idx,
       mbr_name_idx,
       mbr_pwd,
       join_dt
  FROM TB_MEMBER_ENC;

-- 3. 삽입과 수정 -----------------------------------------------------------------
-- 애플리케이션은 평문을 넣고, 트리거가 암호화와 색인 생성을 대신한다.
CREATE OR REPLACE TRIGGER TRG_TB_MEMBER_IOD
INSTEAD OF INSERT OR UPDATE OR DELETE ON TB_MEMBER
FOR EACH ROW
BEGIN
  IF INSERTING THEN
    INSERT INTO TB_MEMBER_ENC (mbr_id, mbr_name_enc, mbr_name_idx,
                               mbr_rrn_enc, mbr_rrn_idx, mbr_phone_enc,
                               mbr_pwd, join_dt)
    VALUES (:NEW.mbr_id,
            OCS_OWNER.PKG_SECURE_API.enc_name(:NEW.mbr_name),
            OCS_OWNER.PKG_SECURE_API.idx_name(:NEW.mbr_name),
            OCS_OWNER.PKG_SECURE_API.enc_rrn(:NEW.mbr_rrn),
            OCS_OWNER.PKG_SECURE_API.idx_rrn(:NEW.mbr_rrn),
            OCS_OWNER.PKG_SECURE_API.protect('PHONE', :NEW.mbr_phone),
            :NEW.mbr_pwd,
            NVL(:NEW.join_dt, SYSDATE));

  ELSIF UPDATING THEN
    UPDATE TB_MEMBER_ENC
       SET mbr_name_enc  = OCS_OWNER.PKG_SECURE_API.enc_name(:NEW.mbr_name),
           mbr_name_idx  = OCS_OWNER.PKG_SECURE_API.idx_name(:NEW.mbr_name),
           mbr_rrn_enc   = OCS_OWNER.PKG_SECURE_API.enc_rrn(:NEW.mbr_rrn),
           mbr_rrn_idx   = OCS_OWNER.PKG_SECURE_API.idx_rrn(:NEW.mbr_rrn),
           mbr_phone_enc = OCS_OWNER.PKG_SECURE_API.protect('PHONE', :NEW.mbr_phone),
           mbr_pwd       = :NEW.mbr_pwd
     WHERE mbr_id = :OLD.mbr_id;

  ELSIF DELETING THEN
    DELETE FROM TB_MEMBER_ENC WHERE mbr_id = :OLD.mbr_id;
  END IF;
END;
/

-- 4. 쿼리 변환 예시 ---------------------------------------------------------------
--
-- 고치기 전 (전 행을 복호화한 뒤 비교한다. 인덱스를 쓰지 못한다)
--
--   SELECT * FROM TB_MEMBER WHERE mbr_rrn = '880101-1234567';
--
-- 고친 뒤 (색인 컬럼으로 인덱스를 타고 한 건만 찾는다)
--
--   SELECT * FROM TB_MEMBER
--    WHERE mbr_rrn_idx = OCS_OWNER.PKG_SECURE_API.idx_rrn('880101-1234567');
--
-- 구분자가 있든 없든 같은 색인 값이 나오므로, 아래 두 구문은 같은 행을 찾는다.
--
--   ... idx_rrn('880101-1234567')  =  ... idx_rrn('8801011234567')
--
-- 범위 검색과 부분 일치 검색은 지원하지 않는다. 그런 요건이 있다면 업무 협의로
-- 축소하는 편이 낫다. 보조 색인을 늘릴수록 정보 노출 면적도 함께 늘어난다.
