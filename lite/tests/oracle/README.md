# 시험 인스턴스에서 확인할 항목

`lite/docs/05_검증기록.md`의 "아직 확인하지 못한 것"을 하나씩 확인하는 절차입니다. 이 폴더의 스크립트는 **시험 인스턴스 전용**입니다. 설치 패키지에는 담기지 않습니다. T4는 키를 교체하며 되돌릴 수 없으므로 운영 데이터베이스에서 실행하면 안 됩니다. 스크립트는 영문 ASCII로만 쓰여 있어 `NLS_LANG` 설정과 무관하게 실행됩니다. 이 폴더로 이동한 뒤 SQL*Plus를 실행하십시오.

```
cd lite\tests\oracle        (리눅스: cd lite/tests/oracle)
```

## 실행 순서

| 순서 | 확인 항목 | 접속 | 실행 | 기대 결과 |
|---|---|---|---|---|
| 1 | 전환 검증 질의(`DECODE`) | `SFC_OWNER` | `@T1_decode_check.sql` | `PASS T1 …` 와 `rows counted by the manual query : 3 (ids 2,3,4)` |
| 2 | 업무 스키마의 함수 호출과 접근 차단 | 업무 스키마 | `@T2_app_calls.sql` | `--- pass 12, fail 0` 와 `T2 OK` |
| 3 | 비밀번호 해시 소요 시간 | `SFC_OWNER` | 아래 3번 | 시간(초)을 기록 |
| 4 | 문자집합 점검이 어긋난 창에서 멈춤 | `SYS` | 아래 4번 | `ORA-20999` 후 SQL*Plus 종료 |
| 5 | 시험 자료 준비 | `SFC_OWNER` | `@T3_prepare.sql` | 두 행, 키 번호 표시 |
| 6 | 키 교체 | `SFC_OWNER` | `@T4_rotate_key.sql` | `--- pass 6, fail 0` 와 `T4 OK` |
| 7 | 재기동 뒤 복호화 | `SFC_OWNER` | 재기동 후 새 창에서 `@T5_verify_after.sql` | `T5 OK (3 rows)` |
| 8 | 재컴파일 때 `ORA-04068` | 두 창 | 아래 8번 | 오류 메시지를 그대로 기록 |
| 9 | 백업 복구본에서 복호화 | `SFC_OWNER` (복구본) | 아래 9번 | `T5 OK (3 rows)` |
| 10 | 정리 | `SFC_OWNER` | `@T6_cleanup.sql` | `T6 done` |

2번은 먼저 `SYS`에서 `@40_connect_app.sql 업무스키마`를 실행해 두어야 합니다(설치 순서 7번). 실패하거나 오류가 나면 거기서 멈추고 출력 전체를 알려 주십시오. 뒤 항목은 앞 항목에 기대지 않는 것이 대부분이지만 5~10번은 순서대로 해야 합니다. 10번은 9번까지 끝낸 뒤에 합니다. 복구 시험이 5번에서 만든 표를 쓰기 때문입니다.

## 3. 비밀번호 해시 소요 시간

```sql
SET TIMING ON
SELECT PKG_SFC.pwd_hash_hex('measure', NULL, 10000)  FROM DUAL;
SELECT PKG_SFC.pwd_hash_hex('measure', NULL, 100000) FROM DUAL;
SELECT PKG_SFC.pwd_hash_hex('measure', NULL, 600000) FROM DUAL;
```

세 줄의 `Elapsed` 시간을 알려 주십시오. 60만 회가 너무 오래 걸리면 중간에 `Ctrl+C`로 끊고 걸린 시간만 알려 주셔도 됩니다. 이 값으로 운영 횟수를 정합니다(안내서 4.2절).

## 4. 문자집합 점검의 부정 경로

저장소의 `lite\sql\05_check_charset.sql`(UTF-8 원본)을 대상으로 합니다. 클라이언트 설정을 일부러 틀리게 하고 실행합니다. 설치 패키지의 CP949 파일로 하려면 반대로 `AL32UTF8`로 맞춥니다.

```
set NLS_LANG=KOREAN_KOREA.KO16MSWIN949
sqlplus / as sysdba
SQL> @..\..\sql\05_check_charset.sql        (리눅스: @../../sql/05_check_charset.sql)
```

원본은 UTF-8인데 위 설정은 CP949이므로 어긋난 상태입니다. 기대 결과는 `ORA-20999 Client character set does not match the file encoding` 이고 SQL*Plus가 종료되는 것입니다. 아무 일 없이 끝나면 점검이 작동하지 않는 것이므로 화면 전체를 알려 주십시오. 이어서 같은 파일을 `set NLS_LANG=KOREAN_KOREA.AL32UTF8`로 맞추고 다시 실행하면 아무 메시지 없이 끝나야 합니다. 콘솔이 UTF-8을 표시하지 못해 화면이 깨져 보일 수 있으나 실행에는 영향이 없습니다. 이 경우 `chcp 65001`을 먼저 실행하십시오.

## 8. 재컴파일 때 `ORA-04068`

창 두 개가 필요합니다. 안내서 제8장이 이 동작을 전제로 쓰여 있으므로 실제로 어떻게 나오는지 확인하는 것이 목적입니다.

1. 창 A에서 업무 스키마로 접속하고 `SELECT FN_SFC_ENC('1') FROM DUAL;`을 실행합니다. 접속은 끊지 않습니다.
2. 창 B에서 `SFC_OWNER`로 접속하고 `ALTER PACKAGE PKG_SFC COMPILE BODY;`를 실행합니다.
3. 창 A에서 같은 `SELECT`를 **두 번** 실행합니다.

첫 번째 실행에서 `ORA-04068`(또는 `ORA-04061`, `ORA-06508`) 계열 오류가 나고 두 번째는 정상이면 안내서와 같은 동작입니다. 첫 번째가 오류 없이 성공해도 중요한 결과이므로 그대로 알려 주십시오. 오류 메시지는 한 줄도 줄이지 말고 붙여 주십시오.

## 9. 백업 복구본에서 복호화

5~6번을 마친 뒤 데이터베이스를 백업하고, 별도 시험 데이터베이스에 복구해서 그 복구본의 `SFC_OWNER`로 접속해 `@T5_verify_after.sql`을 실행합니다. 백업은 가능하면 RMAN으로 복구하는 것이 가장 낫습니다. 단순히 PDB를 복제하는 방식(`CREATE PLUGGABLE DATABASE … FROM …`)은 키, 봉인값, 자료가 함께 움직이는지만 보여 주고 백업과 복구 절차 자체는 시험하지 못하므로 증거가 약합니다. 어느 방식으로 했는지 함께 알려 주십시오.

선택 사항으로, 키가 자료를 따라가지 않는 경우의 보호도 확인할 수 있습니다. 표 `SFC_T_PERSIST`만 다른 데이터베이스로 `expdp`와 `impdp`로 옮기고(`SFC_KEY`와 `SFC_SEAL`은 옮기지 않고) 거기서 암호문을 복호화하면 `ORA-20602`가 나야 합니다. 안내서 제8장의 "일부 스키마만 복제하면 암호문을 읽을 수 없다"는 설명을 확인하는 시험입니다.

## 함께 알려 주실 환경 정보

`SYS`로 접속해 다음 두 줄의 결과를 알려 주십시오. 운영 환경과 같은 조건인지 판단하는 근거가 됩니다. 사용한 운영체제와 `NLS_LANG`, 설치한 패키지의 `VERSION` 파일에 적힌 소스 판도 함께 알려 주십시오.

```sql
SELECT banner_full FROM v$version;
SELECT value FROM nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET';
```

결과를 받으면 `lite/docs/05_검증기록.md`와 안내서 0장의 상태 표를 갱신하고 설치 패키지를 다시 만들겠습니다.
