-- 고정 시험 벡터 적재용 테이블
-- OCS_OWNER 계정으로 실행한다. 시험 환경에만 만들며, 운영 배포 대상이 아니다.

BEGIN
  EXECUTE IMMEDIATE 'DROP TABLE SEC_KAT PURGE';
EXCEPTION
  WHEN OTHERS THEN IF SQLCODE != -942 THEN RAISE; END IF;
END;
/

CREATE TABLE SEC_KAT (
  kat_name  VARCHAR2(60)   NOT NULL,
  kat_value VARCHAR2(4000),
  CONSTRAINT pk_sec_kat PRIMARY KEY (kat_name)
);

COMMENT ON TABLE SEC_KAT IS
  '참조 구현(tools/refimpl)이 생성한 고정 시험 벡터. 시험 전용이며 실제 키가 아니다.';
