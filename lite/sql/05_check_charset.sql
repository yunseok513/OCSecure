-- OCS-LITE client character set check. Every script calls this first (@@05_check_charset.sql).
WHENEVER SQLERROR EXIT FAILURE
DECLARE
  v_probe VARCHAR2(10) := '가';
BEGIN
  IF ASCIISTR(v_probe) <> '\AC00' THEN
    RAISE_APPLICATION_ERROR(-20999,
      'Client character set does not match the file encoding. '
      || 'Set NLS_LANG to match (for CP949 files: KOREAN_KOREA.KO16MSWIN949) and run again.');
  END IF;
END;
/
WHENEVER SQLERROR CONTINUE

-- 클라이언트 문자집합 점검
--
-- 이 폴더의 SQL 파일은 한글 주석이 있으며 설치 패키지에서는 CP949 로 저장되어 있습니다.
-- 클라이언트의 문자집합(NLS_LANG)이 파일 저장 형식과 다르면 한글 주석이 줄바꿈을
-- 삼켜 뒤따르는 줄이 조용히 사라지는 사고가 날 수 있습니다. 이 점검은 위의 '가' 한 글자가
-- 올바르게 읽히는지 보고, 아니면 설치를 멈춥니다.
--
-- 멈췄을 때 조치: SQL*Plus 를 실행하는 창에서 NLS_LANG 을 맞춘 뒤 다시 실행합니다.
--   CP949 파일(설치 패키지 기본)   리눅스  export NLS_LANG=KOREAN_KOREA.KO16MSWIN949
--                                 윈도우  set NLS_LANG=KOREAN_KOREA.KO16MSWIN949
-- 파일을 UTF-8 로 바꿔 쓰는 경우에는 KOREAN_KOREA.AL32UTF8 로 맞춥니다. 두 가지를 섞으면 안 됩니다.
