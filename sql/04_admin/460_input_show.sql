-- 460_appctx_key.sql 의 보조 스크립트. 직접 실행하지 않는다.
-- 입력을 화면에 보이게 받는다. 값이 화면과 스크롤백에 남으므로 개발·시험에서만 쓴다.
ACCEPT k_enc CHAR PROMPT '  1) 예비 키 1 (16진 64자): '
ACCEPT k_mac CHAR PROMPT '  2) 예비 키 2 (16진 64자): '
ACCEPT k_idx CHAR PROMPT '  3) 증표용 키  (16진 64자): '
