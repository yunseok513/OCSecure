-- OCSecure 메타데이터 테이블
-- OCS_OWNER 계정으로 실행한다.
--
-- 이 스키마에는 평문이 저장되지 않는다. 키는 모두 마스터 키로 감싼 상태로만
-- 보관하며, 마스터 키 자체는 데이터베이스 안에 존재하지 않는다.

-- 1. 설정 --------------------------------------------------------------------
CREATE TABLE SEC_CONFIG (
  cfg_key       VARCHAR2(40)  NOT NULL,
  cfg_value     VARCHAR2(200) NOT NULL,
  description   VARCHAR2(400),
  updated_at    TIMESTAMP(6)  DEFAULT SYSTIMESTAMP NOT NULL,
  CONSTRAINT pk_sec_config PRIMARY KEY (cfg_key)
);

INSERT INTO SEC_CONFIG (cfg_key, cfg_value, description) VALUES
  ('KEK_SOURCE', 'EXTERNAL',
   '마스터 키 반입 방식. EXTERNAL 은 외부 키 관리 서버(운영), GLOBAL_CTX 는 직접 주입(개발 전용).');
INSERT INTO SEC_CONFIG (cfg_key, cfg_value, description) VALUES
  ('PWD_ITERATIONS', '10000',
   '비밀번호 키 유도 반복 횟수. 개통 전 실측하여 응답 시간이 허용하는 최대값으로 올린다.');
INSERT INTO SEC_CONFIG (cfg_key, cfg_value, description) VALUES
  ('FAIL_DELAY_CS', '0',
   '복호화 실패 시 지연 시간(1/100초). 대량 시도 억제용. 0이면 지연하지 않는다.');
INSERT INTO SEC_CONFIG (cfg_key, cfg_value, description) VALUES
  ('APPCTX_MODE', 'PROOF',
   '애플리케이션 문맥 설정 방식. PROOF 는 증표 검증(운영), SIMPLE 은 검증 없음(개발 전용).');
INSERT INTO SEC_CONFIG (cfg_key, cfg_value, description) VALUES
  ('APPCTX_WINDOW_SEC', '300',
   '증표 유효 시간(초). 이 시간을 넘긴 증표는 거부하여 재사용을 막는다.');
INSERT INTO SEC_CONFIG (cfg_key, cfg_value, description) VALUES
  ('USAGE_BUCKET_MIN', '60',
   '복호화 사용량 집계 구간(분). 이 구간 단위로 도메인별 임계치를 판정한다.');

-- 2. 도메인 정책 --------------------------------------------------------------
-- 컬럼의 성격별로 키와 정책을 분리한다. 한 키의 유출이 전체로 번지지 않게 한다.
CREATE TABLE SEC_DOMAIN (
  domain_code      VARCHAR2(30) NOT NULL,
  description      VARCHAR2(200),
  alg_id           NUMBER(3)    DEFAULT 1 NOT NULL,
  norm_mode        VARCHAR2(12) DEFAULT 'NONE' NOT NULL,
  mask_type        VARCHAR2(20) DEFAULT 'ALL'  NOT NULL,
  require_app_ctx  CHAR(1)      DEFAULT 'Y'    NOT NULL,
  reveal_limit     NUMBER       DEFAULT 0      NOT NULL,
  audit_level      VARCHAR2(10) DEFAULT 'SUMMARY' NOT NULL,
  created_at       TIMESTAMP(6) DEFAULT SYSTIMESTAMP NOT NULL,
  CONSTRAINT pk_sec_domain      PRIMARY KEY (domain_code),
  CONSTRAINT ck_sec_domain_norm CHECK (norm_mode IN ('NONE','TRIM','UPPER_TRIM','DIGITS')),
  CONSTRAINT ck_sec_domain_mask CHECK (mask_type IN ('ALL','RRN','NAME','ACCOUNT','EMAIL','PHONE')),
  CONSTRAINT ck_sec_domain_ctx  CHECK (require_app_ctx IN ('Y','N')),
  CONSTRAINT ck_sec_domain_aud  CHECK (audit_level IN ('NONE','SUMMARY','FULL')),
  CONSTRAINT ck_sec_domain_lim  CHECK (reveal_limit >= 0)
);

COMMENT ON COLUMN SEC_DOMAIN.norm_mode IS
  '블라인드 인덱스 계산 전 정규화 방식. 구분자 유무와 무관하게 검색되게 한다.';
COMMENT ON COLUMN SEC_DOMAIN.reveal_limit IS
  '집계 구간당 복호화 허용 건수. 0은 무제한. 정상 사용량 관측 후에 설정한다.';

-- 3. 복호화 허용 정책 ---------------------------------------------------------
-- 어떤 역할이 어떤 도메인을 평문으로 볼 수 있는지. 기본은 불허이며 여기 있는
-- 항목만 허용된다. 전면 허용에서 위험한 것을 빼는 방식은 반드시 누락을 낳는다.
CREATE TABLE SEC_REVEAL_GRANT (
  domain_code   VARCHAR2(30) NOT NULL,
  grantee_type  VARCHAR2(10) NOT NULL,   -- ROLE 또는 USER
  grantee_name  VARCHAR2(128) NOT NULL,
  granted_at    TIMESTAMP(6) DEFAULT SYSTIMESTAMP NOT NULL,
  expires_at    TIMESTAMP(6),            -- 한시 권한의 만료. NULL 이면 상시
  granted_by    VARCHAR2(128) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER') NOT NULL,
  reason        VARCHAR2(400),
  CONSTRAINT pk_sec_reveal_grant PRIMARY KEY (domain_code, grantee_type, grantee_name),
  CONSTRAINT fk_sec_reveal_grant FOREIGN KEY (domain_code) REFERENCES SEC_DOMAIN (domain_code),
  CONSTRAINT ck_sec_reveal_gtype CHECK (grantee_type IN ('ROLE','USER'))
);

COMMENT ON COLUMN SEC_REVEAL_GRANT.expires_at IS
  '한시 권한의 만료 시각. 장애 대응용 임시 권한이 회수되지 않고 누적되는 것을 막는다.';

-- 3의2. 관리 권한 -------------------------------------------------------------
-- 키 생성과 정책 변경과 재암호화를 누가 할 수 있는지. 역할은 소유자 권한 패키지
-- 안에서 비활성이므로, 역할 소속은 V_SEC_SESSION_ROLES 로 풀어서 판정한다.
CREATE TABLE SEC_ADMIN_GRANT (
  privilege     VARCHAR2(20)  NOT NULL,   -- KEY_ADMIN / POLICY_ADMIN / REKEY
  grantee_type  VARCHAR2(10)  NOT NULL,
  grantee_name  VARCHAR2(128) NOT NULL,
  granted_at    TIMESTAMP(6)  DEFAULT SYSTIMESTAMP NOT NULL,
  expires_at    TIMESTAMP(6),
  granted_by    VARCHAR2(128) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER') NOT NULL,
  reason        VARCHAR2(400),
  CONSTRAINT pk_sec_admin_grant  PRIMARY KEY (privilege, grantee_type, grantee_name),
  CONSTRAINT ck_sec_admin_priv   CHECK (privilege IN ('KEY_ADMIN','POLICY_ADMIN','REKEY')),
  CONSTRAINT ck_sec_admin_gtype  CHECK (grantee_type IN ('ROLE','USER'))
);

-- 4. 키 저장소 ----------------------------------------------------------------
-- 세 벌의 키를 도메인마다 둔다. 암호화용, 무결성용, 색인용이며 용도를 섞지 않는다.
CREATE TABLE SEC_KEY (
  key_id           NUMBER(5)    NOT NULL,
  domain_code      VARCHAR2(30) NOT NULL,
  alg_id           NUMBER(3)    NOT NULL,
  key_state        VARCHAR2(10) NOT NULL,
  enc_key_wrapped  RAW(256)     NOT NULL,
  mac_key_wrapped  RAW(256)     NOT NULL,
  idx_key_wrapped  RAW(256)     NOT NULL,
  created_at       TIMESTAMP(6) DEFAULT SYSTIMESTAMP NOT NULL,
  created_by       VARCHAR2(128) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER') NOT NULL,
  activated_at     TIMESTAMP(6),
  retired_at       TIMESTAMP(6),
  note             VARCHAR2(400),
  CONSTRAINT pk_sec_key       PRIMARY KEY (key_id),
  CONSTRAINT fk_sec_key_dom   FOREIGN KEY (domain_code) REFERENCES SEC_DOMAIN (domain_code),
  CONSTRAINT ck_sec_key_state CHECK (key_state IN ('ACTIVE','RETIRING','RETIRED')),
  CONSTRAINT ck_sec_key_id    CHECK (key_id BETWEEN 1 AND 65535)
);

-- 도메인당 활성 키는 하나뿐이어야 한다. 둘이면 어느 키로 암호화할지 결정할 수 없다.
CREATE UNIQUE INDEX ux_sec_key_active
  ON SEC_KEY (CASE WHEN key_state = 'ACTIVE' THEN domain_code END);

CREATE INDEX ix_sec_key_domain ON SEC_KEY (domain_code, key_state);

COMMENT ON COLUMN SEC_KEY.key_state IS
  'ACTIVE 는 신규 암호화에 사용, RETIRING 은 복호화 전용, RETIRED 는 사용 중지.';
COMMENT ON COLUMN SEC_KEY.enc_key_wrapped IS
  '마스터 키로 감싼 데이터 암호화 키. 평문 키는 어떤 경우에도 저장하지 않는다.';

-- 1부터 99까지는 자체 시험과 수동 이관용으로 남겨 둔다. 운영 키는 100번부터 받는다.
CREATE SEQUENCE SEQ_SEC_KEY_ID START WITH 100 INCREMENT BY 1 MAXVALUE 65535 NOCYCLE NOCACHE;

-- 5. 감사 로그 ----------------------------------------------------------------
-- 평문과 키는 어떤 경우에도 이 테이블에 기록하지 않는다. 코드 검토의 필수 항목이다.
CREATE TABLE SEC_AUDIT_LOG (
  log_id        NUMBER        GENERATED ALWAYS AS IDENTITY,
  event_ts      TIMESTAMP(6)  DEFAULT SYSTIMESTAMP NOT NULL,
  event_type    VARCHAR2(30)  NOT NULL,
  severity      VARCHAR2(10)  DEFAULT 'INFO' NOT NULL,
  domain_code   VARCHAR2(30),
  db_user       VARCHAR2(128),
  os_user       VARCHAR2(128),
  host_name     VARCHAR2(128),
  ip_address    VARCHAR2(45),
  module_name   VARCHAR2(128),
  session_id    NUMBER,
  app_user      VARCHAR2(128),
  affected_cnt  NUMBER,
  detail        VARCHAR2(400),
  CONSTRAINT pk_sec_audit_log PRIMARY KEY (log_id),
  CONSTRAINT ck_sec_audit_sev CHECK (severity IN ('INFO','WARN','ALERT'))
);

CREATE INDEX ix_sec_audit_ts   ON SEC_AUDIT_LOG (event_ts);
CREATE INDEX ix_sec_audit_type ON SEC_AUDIT_LOG (event_type, event_ts);
CREATE INDEX ix_sec_audit_user ON SEC_AUDIT_LOG (db_user, event_ts);

COMMENT ON TABLE SEC_AUDIT_LOG IS
  '감사 기록. 생성 즉시 외부 관제로 전송해야 하며 이 테이블만으로는 통제가 성립하지 않는다.';
COMMENT ON COLUMN SEC_AUDIT_LOG.detail IS
  '사건 설명. 평문, 키, 암호문 전체를 기록하지 말 것.';

-- 6. 복호화 사용량 -------------------------------------------------------------
-- 전건 기록 대신 구간별 집계를 남긴다. 임계치 판정과 이상 징후 탐지의 근거가 된다.
CREATE TABLE SEC_REVEAL_USAGE (
  db_user      VARCHAR2(128) NOT NULL,
  domain_code  VARCHAR2(30)  NOT NULL,
  bucket_ts    DATE          NOT NULL,
  reveal_cnt   NUMBER        DEFAULT 0 NOT NULL,
  denied_cnt   NUMBER        DEFAULT 0 NOT NULL,
  updated_at   TIMESTAMP(6)  DEFAULT SYSTIMESTAMP NOT NULL,
  CONSTRAINT pk_sec_reveal_usage PRIMARY KEY (db_user, domain_code, bucket_ts)
);

-- 7. 재암호화 작업 -------------------------------------------------------------
-- 키 교체와 알고리즘 교체에 공통으로 쓴다. 중단되어도 이어서 수행할 수 있어야 한다.
CREATE TABLE SEC_REKEY_JOB (
  job_id        NUMBER        GENERATED ALWAYS AS IDENTITY,
  job_name      VARCHAR2(60)  NOT NULL,
  owner_name    VARCHAR2(128) NOT NULL,
  table_name    VARCHAR2(128) NOT NULL,
  pk_column     VARCHAR2(128) NOT NULL,
  cipher_column VARCHAR2(128) NOT NULL,
  index_column  VARCHAR2(128),
  domain_code   VARCHAR2(30)  NOT NULL,
  target_key_id NUMBER(5)     NOT NULL,
  batch_size    NUMBER        DEFAULT 1000 NOT NULL,
  last_pk       VARCHAR2(400),
  done_cnt      NUMBER        DEFAULT 0 NOT NULL,
  status        VARCHAR2(12)  DEFAULT 'READY' NOT NULL,
  last_error    VARCHAR2(400),
  started_at    TIMESTAMP(6),
  updated_at    TIMESTAMP(6)  DEFAULT SYSTIMESTAMP NOT NULL,
  CONSTRAINT pk_sec_rekey_job   PRIMARY KEY (job_id),
  CONSTRAINT uk_sec_rekey_job   UNIQUE (job_name),
  CONSTRAINT fk_sec_rekey_dom   FOREIGN KEY (domain_code) REFERENCES SEC_DOMAIN (domain_code),
  CONSTRAINT ck_sec_rekey_state CHECK (status IN ('READY','RUNNING','PAUSED','DONE','ERROR'))
);

COMMENT ON COLUMN SEC_REKEY_JOB.last_pk IS
  '마지막으로 처리한 기본 키 값. 중단 후 재시작 지점이 된다.';
