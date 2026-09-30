-- 저장값의 반복 횟수 분포
-- OCS_OWNER 계정으로 실행한다.
--
-- 이미 운영 중이어서 비밀번호 저장값이 쌓여 있을 때 쓴다. 저장값마다 만들어질
-- 당시의 반복 횟수가 들어 있으므로, 설정을 올린 뒤 옛 세기로 남아 있는 이용자가
-- 얼마나 되는지 셀 수 있다. 개통 전이라 저장값이 없으면 쓸 일이 없다.
--
-- 대상 컬럼이 RAW 인 경우를 전제한다. 이행 기간처럼 16진 문자열로 저장한
-- 경우에는 아래 조회에서 컬럼 자리를 HEXTORAW(컬럼명) 으로 바꾸어야 한다.

SET FEEDBACK OFF

PROMPT     대상 테이블과 컬럼을 입력한다. 예) TB_USER 와 USER_PWD
ACCEPT tbl CHAR PROMPT '  테이블(스키마.테이블): '
ACCEPT col CHAR PROMPT '  비밀번호 컬럼명      : '

-- 저장값의 3번째 바이트부터 4바이트가 반복 횟수다. 복호화가 아니라 단순 판독이므로
-- 비밀번호를 알아내는 것과는 무관하다.
SELECT UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(&col, 3, 4)) AS iterations,
       COUNT(*)                                                   AS user_cnt
  FROM &tbl
 WHERE &col IS NOT NULL
   AND UTL_RAW.LENGTH(&col) = 54
 GROUP BY UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(&col, 3, 4))
 ORDER BY 1;

PROMPT
PROMPT     위 목록에 현재 설정보다 낮은 횟수가 남아 있다면, 그 사용자들은 아직
PROMPT     옛 세기로 보호되고 있다. 로그인 성공 시점에 다시 계산하도록 애플리케이션이
PROMPT     처리하고 있는지 확인한다. 처리하고 있다면 시간이 지나며 줄어든다.


SET FEEDBACK ON
