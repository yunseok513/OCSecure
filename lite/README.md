# OCS-LITE (간이 암호화 모듈)

기존 전체판(`sql/`, `java/`, `docs/`)과 별개로, 예산과 유지보수 범위가 작은 현장을 위한 간이판입니다. 설계 근거는 `lite/docs/`에 있습니다.

## 설치 순서

| 순서 | 계정 | 파일 |
|---|---|---|
| 1 | SYS | `@10_sys_setup.sql <소유계정 암호> <테이블스페이스>` |
| 2 | SFC_OWNER | `@20_key_table.sql` |
| 3 | SFC_OWNER | `@21_seal.sql` (한 번만. 두 번째는 스스로 거부) |
| 4 | SFC_OWNER | `@22_pkg_sfc.sql` 그리고 `@23_functions.sql` |
| 5 | SFC_OWNER | `@30_init_key.sql` |
| 6 | SFC_OWNER | `@50_selftest.sql` (FAIL 이 한 줄이라도 있으면 배포하지 않음) |
| 7 | SYS | `@40_connect_app.sql <업무 스키마>` |

5번 뒤에는 데이터베이스 전체를 백업합니다. 봉인값과 키를 잃으면 암호화된 자료를 복구할 방법이 없습니다.

## 사용

```sql
INSERT INTO t (rrn_enc, pw_hash) VALUES (FN_SFC_ENC('9001011234567'), FN_SFC_PWD_HASH('pw'));
SELECT FN_SFC_DEC(rrn_enc), FN_SFC_MASK(rrn_enc, 'RRN') FROM t;
SELECT FN_SFC_PWD_VERIFY('pw', pw_hash) FROM t;   -- 1 또는 0
```

암호문 컬럼은 `VARCHAR2`이며 주민등록번호는 136, 계좌번호(20자)는 168, 비밀번호 해시는 108 이상으로 잡습니다. 자세한 표는 `docs/03_구성설계.md`에 있습니다.

## 문서

유지보수업체에 전달하는 안내서는 `docs/04_안내서.md`입니다. 설계 근거는 `docs/01`부터 `03`까지에 있습니다.

## 오라클 없이 하는 점검

```
python3 -W ignore -I -m unittest discover -s lite/tests
```

고정 시험 벡터가 파이썬 참조 구현과 일치하는지, SQL 이 ASCII 만 쓰는지, 패키지 명세와 본문이 맞는지를 봅니다. 컴파일과 실행을 대신하지는 못합니다.
