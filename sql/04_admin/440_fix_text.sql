-- 한글 설명문 복구
-- OCS_OWNER 계정으로 실행한다.
--
-- 020_tables.sql 을 UTF-8 인코딩 그대로 실행하면, 데이터베이스 문자집합이
-- KO16MSWIN949 인 곳에서는 저장된 한글 설명문이 깨진다. 표와 컬럼은 정상이고
-- 설명문만 깨지므로 동작에는 지장이 없으나, 관리 화면과 점검 문서에 그대로
-- 노출되므로 바로잡는다.
--
-- 이 파일을 CP949 로 바꾸어 실행하거나, NLS_LANG 을 KOREAN_KOREA.AL32UTF8 로
-- 두고 실행한다. docs/저장소/빌드_및_시험_설명서.md 제6.1절을 볼 것. 자료는 건드리지 않으며 설명문만
-- 다시 쓴다. 몇 번을 실행해도 결과가 같다.

SET FEEDBACK OFF
SET DEFINE OFF

PROMPT === 설정 항목 설명문 ===

UPDATE SEC_CONFIG SET description =
  '마스터 키 반입 방식. EXTERNAL 은 외부 키 관리 서버(운영), GLOBAL_CTX 는 직접 주입(개발 전용).'
 WHERE cfg_key = 'KEK_SOURCE';

UPDATE SEC_CONFIG SET description =
  '비밀번호 키 유도 반복 횟수. 개통 전 실측하여 응답 시간이 허용하는 최대값으로 올린다.'
 WHERE cfg_key = 'PWD_ITERATIONS';

UPDATE SEC_CONFIG SET description =
  '복호화 실패 시 지연 시간(1/100초). 대량 시도 억제용. 0이면 지연하지 않는다.'
 WHERE cfg_key = 'FAIL_DELAY_CS';

UPDATE SEC_CONFIG SET description =
  '기존 비밀번호 체계가 쓰던 문자집합. 이행 전에 PKG_LEGACY_PWD.self_check 로 확정한다.'
 WHERE cfg_key = 'LEGACY_PWD_CHARSET';

UPDATE SEC_CONFIG SET description =
  '애플리케이션 문맥 설정 방식. PROOF 는 증표 검증(운영), SIMPLE 은 검증 없음(개발 전용).'
 WHERE cfg_key = 'APPCTX_MODE';

UPDATE SEC_CONFIG SET description =
  '증표 유효 시간(초). 이 시간을 넘긴 증표는 거부하여 재사용을 막는다.'
 WHERE cfg_key = 'APPCTX_WINDOW_SEC';

UPDATE SEC_CONFIG SET description =
  '복호화 사용량 집계 구간(분). 이 구간 단위로 도메인별 임계치를 판정한다.'
 WHERE cfg_key = 'USAGE_BUCKET_MIN';


COMMIT;

PROMPT === 표와 컬럼 주석 ===

COMMENT ON COLUMN SEC_DOMAIN.norm_mode IS
  '블라인드 인덱스 계산 전 정규화 방식. 구분자 유무와 무관하게 검색되게 한다.';

COMMENT ON COLUMN SEC_DOMAIN.reveal_limit IS
  '집계 구간당 복호화 허용 건수. 0은 무제한. 정상 사용량 관측 후에 설정한다.';

COMMENT ON COLUMN SEC_REVEAL_GRANT.expires_at IS
  '한시 권한의 만료 시각. 장애 대응용 임시 권한이 회수되지 않고 누적되는 것을 막는다.';

COMMENT ON COLUMN SEC_KEY.key_state IS
  'ACTIVE 는 신규 암호화에 사용, RETIRING 은 복호화 전용, RETIRED 는 사용 중지.';

COMMENT ON COLUMN SEC_KEY.enc_key_wrapped IS
  '마스터 키로 감싼 데이터 암호화 키. 평문 키는 어떤 경우에도 저장하지 않는다.';

COMMENT ON TABLE SEC_AUDIT_LOG IS
  '감사 기록. 생성 즉시 외부 관제로 전송해야 하며 이 테이블만으로는 통제가 성립하지 않는다.';

COMMENT ON COLUMN SEC_AUDIT_LOG.detail IS
  '사건 설명. 평문, 키, 암호문 전체를 기록하지 말 것.';

COMMENT ON COLUMN SEC_REKEY_JOB.last_pk IS
  '마지막으로 처리한 기본 키 값. 중단 후 재시작 지점이 된다.';


PROMPT
PROMPT 확인: 아래 결과의 설명문이 제대로 읽히면 복구된 것이다.
SELECT cfg_key, description FROM SEC_CONFIG ORDER BY cfg_key;

SET FEEDBACK ON
