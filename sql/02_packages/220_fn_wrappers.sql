-- 함수 이름 계층
-- OCS_OWNER 계정으로 실행한다. 210 까지 만든 뒤에 실행한다.
--
-- 개발자가 쿼리 안에서 패키지 이름 없이 FN_ENC_RRN(...) 처럼 짧은 함수 이름으로
-- 호출할 수 있도록, PKG_SECURE_API 의 함수마다 같은 동작의 단독 함수를 하나씩 둔다.
-- 단독 함수는 인자를 그대로 PKG_SECURE_API 에 넘기고 결과를 그대로 돌려줄 뿐이며,
-- 판단이나 통제를 새로 하지 않는다. 증표 검증, 복호화 자격, 마스킹, 감사는 모두
-- 아래 PKG_SECURE_API 가 그대로 적용한다.
--
-- 이름 규칙은 FN_ 뒤에 PKG_SECURE_API 의 함수 이름을 대문자로 붙인 것이다.
--   FN_ENC_RRN, FN_DEC_RRN, FN_MASK_RRN, FN_IDX_RRN, FN_PROTECT, FN_SHOW ...
--
-- 이 함수들은 OCS_OWNER 소유이므로 응용 스키마에서 이름만으로 쓰려면 실행 권한과
-- 시노님이 필요하다. 권한은 300_grants.sql 이 OCS_ROLE_APP 에 주고, 업무 계정에 대한
-- 직접 권한과 시노님은 04_admin/480_connect_app_schema.sql 이 업무 계정마다 만든다.
--
-- 호출마다 PL/SQL 호출이 한 번 더 들어가므로, 한 쿼리에서 많은 행에 부르는 곳은
-- 필요한 행만 대상으로 줄여야 한다. 이 점은 패키지를 직접 부를 때와 같다.

-- 용도. 도메인 코드를 인자로 받는 일반형 암호화. 표준 도메인 전용 함수(FN_ENC_RRN 등)가 없는
--      도메인(PHONE 등)에 쓴다. 입력이 널이면 널을 돌려준다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 반환은 암호문(RAW).
-- 예시.
--   INSERT INTO t (id, phone_enc) VALUES (1, FN_PROTECT('PHONE', :phone));
CREATE OR REPLACE FUNCTION FN_PROTECT(p_domain_code IN VARCHAR2, p_plain IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.protect(p_domain_code, p_plain);
END FN_PROTECT;
/

-- 용도. 도메인 코드를 인자로 받는 일반형 복호화. 평문을 돌려준다.
-- 동작. 응용 문맥과 복호화 자격이 모두 필요하며 없으면 예외다. 호출은 사용량으로 집계되고 임계치가
--      있다. 목록 화면에는 쓰지 말고 FN_SHOW 나 FN_MASKED 를 쓴다.
-- 예시.
--   SELECT FN_REVEAL('PHONE', phone_enc) FROM t WHERE id = 1;
CREATE OR REPLACE FUNCTION FN_REVEAL(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.reveal(p_domain_code, p_cipher);
END FN_REVEAL;
/

-- 용도. 도메인 코드를 인자로 받는 일반형 마스킹. 자격과 무관하게 언제나 가려진 값을 돌려준다.
-- 동작. 응용 문맥을 검사하지 않고 복호화 자격도 필요 없다. 목록 화면용이다.
-- 예시.
--   SELECT FN_MASKED('PHONE', phone_enc) FROM t;
CREATE OR REPLACE FUNCTION FN_MASKED(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.masked(p_domain_code, p_cipher);
END FN_MASKED;
/

-- 용도. 도메인 코드를 인자로 받는 일반형 조회. 복호화 자격이 있으면 평문을, 없으면 마스킹된 값을
--      돌려준다.
-- 동작. 응용 문맥이 없으면 마스킹된 값을 돌려준다. 평문을 돌려줄 때만 사용량으로 집계된다. 투명화 뷰의
--      기본 선택지다.
-- 예시.
--   SELECT FN_SHOW('PHONE', phone_enc) FROM t;
CREATE OR REPLACE FUNCTION FN_SHOW(p_domain_code IN VARCHAR2, p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.show(p_domain_code, p_cipher);
END FN_SHOW;
/

-- 용도. 도메인 코드를 인자로 받는 일반형 검색용 색인 생성. 같은 평문은 같은 색인이 되므로 색인 컬럼과
--      비교하여 찾는다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 반환은 색인(RAW).
-- 예시.
--   SELECT * FROM t WHERE phone_idx = FN_SEARCH_OF('PHONE', :phone);
CREATE OR REPLACE FUNCTION FN_SEARCH_OF(p_domain_code IN VARCHAR2, p_plain IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.search_of(p_domain_code, p_plain);
END FN_SEARCH_OF;
/

-- 용도. 호출한 세션이 해당 도메인의 평문을 볼 자격이 있는지 물어본다. 판정만 하고 평문을 만들지
--      않는다.
-- 동작. 'Y' 또는 'N' 을 돌려준다. 응용 문맥이 없으면 'N' 이다. 화면 진입 전에 평문 조회
--      가능 여부를 갈라 처리할 때 쓴다.
-- 예시.
--   SELECT FN_ALLOWED('RRN') FROM DUAL;
CREATE OR REPLACE FUNCTION FN_ALLOWED(p_domain_code IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.allowed(p_domain_code);
END FN_ALLOWED;
/

-- 용도. 주민등록번호를 암호화한다. FN_PROTECT('RRN', ...) 와 같다. 입력이 널이면 널을
--      돌려준다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 반환은 암호문(RAW)이며, 같은 평문도 호출할
--      때마다 암호문이 달라진다. 검색을 위해 FN_IDX_RRN 의 색인을 같은 행에 함께 저장한다.
-- 예시.
--   INSERT INTO t (id, rrn_enc, rrn_idx) VALUES (1, FN_ENC_RRN(:v), FN_IDX_RRN(:v));
CREATE OR REPLACE FUNCTION FN_ENC_RRN(p_rrn IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.enc_rrn(p_rrn);
END FN_ENC_RRN;
/

-- 용도. 주민등록번호 암호문을 복호화하여 평문을 돌려준다. FN_REVEAL('RRN', ...) 와
--      같다.
-- 동작. 응용 문맥과 복호화 자격이 모두 필요하며 없으면 예외다. 호출은 사용량으로 집계되고 임계치가
--      있다. 상세 화면 등 꼭 필요한 곳에만 쓰고 목록 화면에는 쓰지 않는다.
-- 예시.
--   SELECT FN_DEC_RRN(rrn_enc) FROM t WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_DEC_RRN(p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.dec_rrn(p_cipher);
END FN_DEC_RRN;
/

-- 용도. 주민등록번호 암호문을 마스킹하여 돌려준다. FN_MASKED('RRN', ...) 와 같다.
-- 동작. 자격과 무관하게 언제나 가려진 값이다. 응용 문맥을 검사하지 않는다. 목록 화면용이다.
-- 예시.
--   SELECT FN_MASK_RRN(rrn_enc) FROM t;
CREATE OR REPLACE FUNCTION FN_MASK_RRN(p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.mask_rrn(p_cipher);
END FN_MASK_RRN;
/

-- 용도. 주민등록번호의 검색용 색인을 만든다. FN_SEARCH_OF('RRN', ...) 와 같다. 같은
--      값은 같은 색인이 되므로 평문으로 찾을 때 색인 컬럼과 비교한다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 암호화 컬럼을 WHERE 에 직접 쓰지 말고 이
--      색인으로 찾는다.
-- 예시.
--   SELECT * FROM t WHERE rrn_idx = FN_IDX_RRN(:v);
CREATE OR REPLACE FUNCTION FN_IDX_RRN(p_rrn IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.idx_rrn(p_rrn);
END FN_IDX_RRN;
/

-- 용도. 계좌번호를 암호화한다. FN_PROTECT('ACCOUNT', ...) 와 같다. 입력이 널이면
--      널을 돌려준다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 반환은 암호문(RAW)이며, 같은 평문도 호출할
--      때마다 암호문이 달라진다. 검색을 위해 FN_IDX_ACCOUNT 의 색인을 같은 행에 함께 저장한다.
-- 예시.
--   INSERT INTO t (id, account_enc, account_idx) VALUES (1, FN_ENC_ACCOUNT(:v), FN_IDX_ACCOUNT(:v));
CREATE OR REPLACE FUNCTION FN_ENC_ACCOUNT(p_account IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.enc_account(p_account);
END FN_ENC_ACCOUNT;
/

-- 용도. 계좌번호 암호문을 복호화하여 평문을 돌려준다. FN_REVEAL('ACCOUNT', ...) 와
--      같다.
-- 동작. 응용 문맥과 복호화 자격이 모두 필요하며 없으면 예외다. 호출은 사용량으로 집계되고 임계치가
--      있다. 상세 화면 등 꼭 필요한 곳에만 쓰고 목록 화면에는 쓰지 않는다.
-- 예시.
--   SELECT FN_DEC_ACCOUNT(account_enc) FROM t WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_DEC_ACCOUNT(p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.dec_account(p_cipher);
END FN_DEC_ACCOUNT;
/

-- 용도. 계좌번호 암호문을 마스킹하여 돌려준다. FN_MASKED('ACCOUNT', ...) 와 같다.
-- 동작. 자격과 무관하게 언제나 가려진 값이다. 응용 문맥을 검사하지 않는다. 목록 화면용이다.
-- 예시.
--   SELECT FN_MASK_ACCOUNT(account_enc) FROM t;
CREATE OR REPLACE FUNCTION FN_MASK_ACCOUNT(p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.mask_account(p_cipher);
END FN_MASK_ACCOUNT;
/

-- 용도. 계좌번호의 검색용 색인을 만든다. FN_SEARCH_OF('ACCOUNT', ...) 와 같다.
--      같은 값은 같은 색인이 되므로 평문으로 찾을 때 색인 컬럼과 비교한다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 암호화 컬럼을 WHERE 에 직접 쓰지 말고 이
--      색인으로 찾는다.
-- 예시.
--   SELECT * FROM t WHERE account_idx = FN_IDX_ACCOUNT(:v);
CREATE OR REPLACE FUNCTION FN_IDX_ACCOUNT(p_account IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.idx_account(p_account);
END FN_IDX_ACCOUNT;
/

-- 용도. 성명를 암호화한다. FN_PROTECT('NAME', ...) 와 같다. 입력이 널이면 널을
--      돌려준다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 반환은 암호문(RAW)이며, 같은 평문도 호출할
--      때마다 암호문이 달라진다. 검색을 위해 FN_IDX_NAME 의 색인을 같은 행에 함께 저장한다.
-- 예시.
--   INSERT INTO t (id, name_enc, name_idx) VALUES (1, FN_ENC_NAME(:v), FN_IDX_NAME(:v));
CREATE OR REPLACE FUNCTION FN_ENC_NAME(p_name IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.enc_name(p_name);
END FN_ENC_NAME;
/

-- 용도. 성명 암호문을 복호화하여 평문을 돌려준다. FN_REVEAL('NAME', ...) 와 같다.
-- 동작. 응용 문맥과 복호화 자격이 모두 필요하며 없으면 예외다. 호출은 사용량으로 집계되고 임계치가
--      있다. 상세 화면 등 꼭 필요한 곳에만 쓰고 목록 화면에는 쓰지 않는다.
-- 예시.
--   SELECT FN_DEC_NAME(name_enc) FROM t WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_DEC_NAME(p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.dec_name(p_cipher);
END FN_DEC_NAME;
/

-- 용도. 성명 암호문을 마스킹하여 돌려준다. FN_MASKED('NAME', ...) 와 같다.
-- 동작. 자격과 무관하게 언제나 가려진 값이다. 응용 문맥을 검사하지 않는다. 목록 화면용이다.
-- 예시.
--   SELECT FN_MASK_NAME(name_enc) FROM t;
CREATE OR REPLACE FUNCTION FN_MASK_NAME(p_cipher IN RAW) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.mask_name(p_cipher);
END FN_MASK_NAME;
/

-- 용도. 성명의 검색용 색인을 만든다. FN_SEARCH_OF('NAME', ...) 와 같다. 같은 값은
--      같은 색인이 되므로 평문으로 찾을 때 색인 컬럼과 비교한다.
-- 동작. 응용 문맥 필요. 복호화 자격은 필요 없다. 암호화 컬럼을 WHERE 에 직접 쓰지 말고 이
--      색인으로 찾는다.
-- 예시.
--   SELECT * FROM t WHERE name_idx = FN_IDX_NAME(:v);
CREATE OR REPLACE FUNCTION FN_IDX_NAME(p_name IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.idx_name(p_name);
END FN_IDX_NAME;
/

-- 용도. 비밀번호를 일방향으로 저장할 값(RAW)으로 만든다. 되돌릴 수 없다.
-- 동작. 새 비밀번호를 저장하거나 변경할 때 쓴다. 비밀번호를 양방향으로 암호화하지 않는다.
-- 예시.
--   UPDATE t SET pwd = FN_MAKE_PWD(:new_password) WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_MAKE_PWD(p_password IN VARCHAR2) RETURN RAW IS
BEGIN
  RETURN PKG_SECURE_API.make_pwd(p_password);
END FN_MAKE_PWD;
/

-- 용도. 입력한 비밀번호가 저장된 값(RAW)과 맞는지 확인한다.
-- 동작. 맞으면 1, 아니면 0 을 돌려준다. SQL 에서 바로 쓸 수 있도록 숫자로 돌려준다.
-- 예시.
--   SELECT FN_VERIFY_PWD(:password, pwd) FROM t WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_VERIFY_PWD(p_password IN VARCHAR2, p_stored IN RAW) RETURN NUMBER IS
BEGIN
  RETURN PKG_SECURE_API.verify_pwd(p_password, p_stored);
END FN_VERIFY_PWD;
/

-- 용도. 저장된 비밀번호 값(RAW)이 현재 기준보다 약한지 본다. 반복 횟수를 올린 뒤 이전 값을
--      점진적으로 갱신할 때 쓴다.
-- 동작. 1 이면 로그인에 성공한 시점에 FN_MAKE_PWD 로 다시 계산해 저장한다. 0 이면 그대로
--      둔다.
-- 예시.
--   SELECT FN_PWD_STALE(pwd) FROM t WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_PWD_STALE(p_stored IN RAW) RETURN NUMBER IS
BEGIN
  RETURN PKG_SECURE_API.pwd_stale(p_stored);
END FN_PWD_STALE;
/

-- 용도. FN_MAKE_PWD 의 문자열판. 결과를 16진 문자열(VARCHAR2)로 돌려준다. 기존
--      컬럼이 문자열일 때 이행 기간에 쓴다.
-- 동작. 이행이 끝나면 FN_CHECK_PWD, FN_PWD_STATE 와 함께 제거한다.
-- 예시.
--   UPDATE t SET pwd_str = FN_MAKE_PWD_STR(:new_password) WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_MAKE_PWD_STR(p_password IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN PKG_SECURE_API.make_pwd_str(p_password);
END FN_MAKE_PWD_STR;
/

-- 용도. 문자열로 저장된 비밀번호 값과 입력을 맞춰 본다. 현재 형식과 옛 형식이 섞여 있는 이행
--      기간용이다.
-- 동작. 0 이면 불일치, 1 이면 일치(현재 형식, 그대로 로그인), 2 이면 일치(옛 형식,
--      로그인시키되 비밀번호 변경을 강제)이다.
-- 예시.
--   SELECT FN_CHECK_PWD(:password, pwd_str) FROM t WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_CHECK_PWD(p_password IN VARCHAR2, p_stored IN VARCHAR2) RETURN NUMBER IS
BEGIN
  RETURN PKG_SECURE_API.check_pwd(p_password, p_stored);
END FN_CHECK_PWD;
/

-- 용도. 문자열로 저장된 비밀번호 값의 상태만 본다. 비밀번호를 입력받기 전에 화면을 고르는 데 쓴다.
-- 동작. 0 이면 미설정(단일 인증 이용자 등, 설정 절차로 보낸다), 1 이면 현재 형식, 2 이면 옛
--      형식(이행 기간에만), 9 이면 알 수 없는 형식(통과시키지 말고 조사한다)이다.
-- 예시.
--   SELECT FN_PWD_STATE(pwd_str) FROM t WHERE id = :id;
CREATE OR REPLACE FUNCTION FN_PWD_STATE(p_stored IN VARCHAR2) RETURN NUMBER IS
BEGIN
  RETURN PKG_SECURE_API.pwd_state(p_stored);
END FN_PWD_STATE;
/

-- 용도. 암복호화를 할 수 있는 상태인지 미리 물어본다. 키 저장소가 닫혀 있으면 모든 호출이 예외를
--      내므로, 화면 진입 전에 이 값을 보고 안내 화면으로 갈라 처리한다.
-- 동작. 1 이면 가능, 0 이면 불가다. 키 값이나 그 밖의 비밀은 드러나지 않는다. 감시 도구의 상태
--      점검에도 쓴다.
-- 예시.
--   SELECT FN_READY FROM DUAL;
CREATE OR REPLACE FUNCTION FN_READY RETURN NUMBER IS
BEGIN
  RETURN PKG_SECURE_API.ready;
END FN_READY;
/
