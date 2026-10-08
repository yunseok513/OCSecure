package ocsecure.client;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 개발자 매뉴얼 제4장(저장, 상세, 목록, 조인과 집계, 임계치), 제5장(비밀번호), 제8장(저장 프로시저),
 * 제9장(예외와 되돌리기)의 예시를 한 번에 돌려 확인한다.
 *
 * <p>임시 표 TB_RCP_A, TB_RCP_B 와 프로시저 SP_RCP_SAVE 를 만들고 끝에 지운다. 시험 값은 실제
 * 개인정보가 아닌 일련번호이다. 증표를 제출해 문맥을 세우므로 운영 방식 그대로 돈다.
 *
 * <p>실행. 마지막 인자 --limit 은 사용량 임계치를 확인하는 선택 항목이며, 키 관리자가 이 계정에
 * 주민등록번호(RRN)의 복호화 자격을 준 뒤에만 쓴다. 끝나면 자격을 거둔다.
 * <pre>
 *   java -cp out;ojdbc8.jar ocsecure.client.OcsRecipeCheck "jdbc:oracle:thin:@호스트:포트/서비스명" 계정 - - [--limit]
 * </pre>
 */
public final class OcsRecipeCheck {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String what, boolean ok) {
        if (ok) { pass++; } else { fail++; }
        System.out.println("  [" + (ok ? "통과" : "실패") + "] " + what);
    }

    private static String secret(String arg, String prompt) {
        if (!"-".equals(arg)) {
            return arg;
        }
        java.io.Console c = System.console();
        if (c == null) {
            throw new IllegalStateException("콘솔이 없어 비밀값을 입력받을 수 없다. 명령 프롬프트에서 실행하십시오.");
        }
        return new String(c.readPassword("%s", prompt));
    }

    private static void ddl(Connection con, String sql) throws SQLException {
        try (Statement st = con.createStatement()) {
            st.execute(sql);
        }
    }

    private static void dropQuietly(Connection con, String sql) {
        try {
            ddl(con, sql);
        } catch (SQLException ignore) {
            // 없으면 그대로 둔다.
        }
    }

    private static long count(Connection con, String sql) throws SQLException {
        try (Statement st = con.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private static String one(Connection con, String sql, String... binds) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            for (int i = 0; i < binds.length; i++) {
                ps.setString(i + 1, binds[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    private static String rrn(int i) {
        return "9001011" + String.format("%06d", i);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("사용법: OcsRecipeCheck <jdbcUrl> <사용자> <암호|-> <증표키16진|-> [--limit]");
            System.exit(2);
        }
        boolean limit = args.length > 4 && "--limit".equals(args[4]);
        String pwd = secret(args[2], "응용 계정 암호: ");
        String keyHex = secret(args[3], "증표 키(16진 64자): ").trim();
        OcsSessionSupport session = new OcsSessionSupport(new OcsAppProof(OcsCrypto.fromHex(keyHex)));

        try (Connection con = DriverManager.getConnection(args[0], args[1], pwd)) {
            con.setAutoCommit(false);
            session.establish(con, "recipe.check");
            System.out.println("=== 개발자 매뉴얼 예시 확인 ===");
            try {
                dropQuietly(con, "DROP TABLE TB_RCP_B PURGE");
                dropQuietly(con, "DROP TABLE TB_RCP_A PURGE");
                dropQuietly(con, "DROP PROCEDURE SP_RCP_SAVE");
                ddl(con, "CREATE TABLE TB_RCP_A (mbr_id NUMBER PRIMARY KEY, dept_cd VARCHAR2(10),"
                        + " mbr_name_enc RAW(256), mbr_name_idx RAW(32), mbr_rrn_enc RAW(256), mbr_rrn_idx RAW(32),"
                        + " mbr_phone_enc RAW(256), mbr_pwd RAW(64))");
                ddl(con, "CREATE TABLE TB_RCP_B (ord_id NUMBER PRIMARY KEY, ord_rrn_idx RAW(32))");

                // 제4.2절: 원본 테이블에 직접 저장. 암호문과 색인을 함께 채운다.
                String ins = "INSERT INTO TB_RCP_A (mbr_id, dept_cd, mbr_name_enc, mbr_name_idx, mbr_rrn_enc, mbr_rrn_idx,"
                        + " mbr_phone_enc, mbr_pwd) VALUES (?, ?, FN_ENC_NAME(?), FN_IDX_NAME(?), FN_ENC_RRN(?), FN_IDX_RRN(?),"
                        + " FN_PROTECT('PHONE', ?), FN_MAKE_PWD(?))";
                try (PreparedStatement ps = con.prepareStatement(ins)) {
                    for (int i = 1; i <= 25; i++) {
                        ps.setInt(1, i);
                        ps.setString(2, i <= 20 ? "D1" : "D2");
                        ps.setString(3, "회원" + i);
                        ps.setString(4, "회원" + i);
                        ps.setString(5, rrn(i));
                        ps.setString(6, rrn(i));
                        ps.setString(7, "010-0000-" + String.format("%04d", i));
                        ps.setString(8, "Pw#" + i);
                        ps.executeUpdate();
                    }
                }
                con.commit();
                check("원본 테이블에 직접 저장했다 (25건)", count(con, "SELECT COUNT(*) FROM TB_RCP_A") == 25);
                check("주민등록번호 암호문은 68바이트, 색인은 32바이트이다",
                        count(con, "SELECT COUNT(*) FROM TB_RCP_A WHERE UTL_RAW.LENGTH(mbr_rrn_enc) = 68"
                                + " AND UTL_RAW.LENGTH(mbr_rrn_idx) = 32") == 25);

                // 제4.3절: 복호화는 자격이 없으면 거부되고, FN_SHOW 는 마스킹을 낸다.
                String can = one(con, "SELECT FN_ALLOWED('RRN') FROM DUAL");
                System.out.println("  복호화 자격(주민등록번호): " + ("Y".equals(can) ? "있음" : "없음"));
                if (!"Y".equals(can)) {
                    try {
                        one(con, "SELECT FN_REVEAL('RRN', mbr_rrn_enc) FROM TB_RCP_A WHERE mbr_id = 1");
                        check("자격이 없으면 FN_REVEAL 이 거부된다", false);
                    } catch (SQLException e) {
                        check("자격이 없으면 FN_REVEAL 이 거부된다 (ORA-" + e.getErrorCode() + ")", e.getErrorCode() == 20520);
                    }
                    String shown = one(con, "SELECT FN_SHOW('RRN', mbr_rrn_enc) FROM TB_RCP_A WHERE mbr_id = 1");
                    check("FN_SHOW 는 마스킹을 낸다 (" + shown + ")", (rrn(1).substring(0, 8) + "******").equals(shown));
                }

                // 제4.4절: 안쪽에서 먼저 자르고 바깥에서 마스킹한다.
                long page = 0;
                try (PreparedStatement ps = con.prepareStatement(
                        "SELECT t.mbr_id, FN_MASKED('RRN', t.mbr_rrn_enc) FROM (SELECT mbr_id, mbr_rrn_enc FROM TB_RCP_A"
                        + " WHERE dept_cd = ? ORDER BY mbr_id OFFSET ? ROWS FETCH NEXT ? ROWS ONLY) t ORDER BY t.mbr_id")) {
                    ps.setString(1, "D1");
                    ps.setInt(2, 10);
                    ps.setInt(3, 10);
                    try (ResultSet rs = ps.executeQuery()) {
                        long first = -1;
                        while (rs.next()) {
                            if (first < 0) { first = rs.getLong(1); }
                            page++;
                        }
                        check("둘째 쪽은 11번부터 10건이다 (첫 번호 " + first + ", " + page + "건)", page == 10 && first == 11);
                    }
                }

                // 제4.5절: 색인으로 찾는다. 하이픈이 있든 없든 같다.
                check("색인으로 정확히 한 건을 찾는다 (하이픈 있음/없음)",
                        "1".equals(one(con, "SELECT COUNT(*) FROM TB_RCP_A WHERE mbr_rrn_idx = FN_IDX_RRN(?)", "900101-1000007"))
                     && "1".equals(one(con, "SELECT COUNT(*) FROM TB_RCP_A WHERE mbr_rrn_idx = FN_IDX_RRN(?)", rrn(7))));

                // 제4.7절: 같은 도메인의 색인끼리 조인하고 집계한다.
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO TB_RCP_B (ord_id, ord_rrn_idx) VALUES (?, FN_IDX_RRN(?))")) {
                    int[][] orders = {{1, 3}, {2, 3}, {3, 5}, {4, 3}};
                    for (int[] o : orders) {
                        ps.setInt(1, o[0]);
                        ps.setString(2, rrn(o[1]));
                        ps.executeUpdate();
                    }
                }
                con.commit();
                check("색인끼리 조인하면 주문 4건이 회원과 맞춰진다",
                        count(con, "SELECT COUNT(*) FROM TB_RCP_A a JOIN TB_RCP_B b ON a.mbr_rrn_idx = b.ord_rrn_idx") == 4);
                check("색인으로 묶으면 회원 3번이 3건, 5번이 1건이다",
                        count(con, "SELECT MAX(c) FROM (SELECT COUNT(*) c FROM TB_RCP_B GROUP BY ord_rrn_idx)") == 3
                     && count(con, "SELECT COUNT(*) FROM (SELECT ord_rrn_idx FROM TB_RCP_B GROUP BY ord_rrn_idx)") == 2);

                // 제5장: 비밀번호.
                String len = one(con, "SELECT UTL_RAW.LENGTH(mbr_pwd) FROM TB_RCP_A WHERE mbr_id = 1");
                check("비밀번호 저장값은 54바이트이다", "54".equals(len));
                check("맞는 비밀번호는 1, 틀린 비밀번호는 0 이다",
                        "1".equals(one(con, "SELECT FN_VERIFY_PWD(?, mbr_pwd) FROM TB_RCP_A WHERE mbr_id = 1", "Pw#1"))
                     && "0".equals(one(con, "SELECT FN_VERIFY_PWD(?, mbr_pwd) FROM TB_RCP_A WHERE mbr_id = 1", "Pw#2")));
                String h1 = one(con, "SELECT RAWTOHEX(FN_MAKE_PWD(?)) FROM DUAL", "same");
                String h2 = one(con, "SELECT RAWTOHEX(FN_MAKE_PWD(?)) FROM DUAL", "same");
                check("같은 비밀번호도 저장값은 매번 다르다", h1 != null && !h1.equals(h2));
                check("방금 만든 저장값은 갱신이 필요하지 않다 (FN_PWD_STALE = 0)",
                        "0".equals(one(con, "SELECT FN_PWD_STALE(mbr_pwd) FROM TB_RCP_A WHERE mbr_id = 1")));
                try {
                    one(con, "SELECT FN_MAKE_PWD(?) FROM DUAL", "");
                    check("빈 비밀번호는 거부된다", false);
                } catch (SQLException e) {
                    check("빈 비밀번호는 ORA-20541 로 거부된다 (ORA-" + e.getErrorCode() + ")", e.getErrorCode() == 20541);
                }
            } catch (SQLException e) {
                // 준비나 저장 단계의 예기치 않은 오류. 삼키지 않고 알린다.
                System.out.println("  [중단] ORA-" + e.getErrorCode() + " " + e.getMessage());
                fail++;
            }

            try {
                // 제8.1절: 저장 프로시저 틀.
                ddl(con, "CREATE OR REPLACE PROCEDURE SP_RCP_SAVE(p_id IN NUMBER, p_rrn IN VARCHAR2) IS BEGIN"
                        + " IF FN_READY = 0 THEN RAISE_APPLICATION_ERROR(-20999, '암호 모듈을 쓸 수 없는 상태이다.'); END IF;"
                        + " INSERT INTO TB_RCP_A (mbr_id, mbr_rrn_enc, mbr_rrn_idx) VALUES (p_id, FN_ENC_RRN(p_rrn), FN_IDX_RRN(p_rrn));"
                        + " END;");
                try (CallableStatement cs = con.prepareCall("{ call SP_RCP_SAVE(?, ?) }")) {
                    cs.setInt(1, 101);
                    cs.setString(2, rrn(101));
                    cs.execute();
                }
                con.commit();
                check("저장 프로시저가 컴파일되고 문맥이 선 세션에서 저장한다",
                        count(con, "SELECT COUNT(*) FROM TB_RCP_A WHERE mbr_id = 101 AND mbr_rrn_idx = FN_IDX_RRN('" + rrn(101) + "')") == 1);

                // 제9.1절: 예외는 삼키지 않고 되돌린다. 없는 도메인 코드는 ORA-20530.
                long before = count(con, "SELECT COUNT(*) FROM TB_RCP_A");
                try (PreparedStatement ps = con.prepareStatement(
                        "INSERT INTO TB_RCP_A (mbr_id, mbr_phone_enc) VALUES (?, FN_PROTECT('NOPE', ?))")) {
                    ps.setInt(1, 102);
                    ps.setString(2, "x");
                    ps.executeUpdate();
                    check("없는 도메인 코드는 거부된다", false);
                } catch (SQLException e) {
                    con.rollback();
                    check("없는 도메인 코드는 ORA-20530 으로 거부되고 되돌려진다",
                            e.getErrorCode() == 20530 && count(con, "SELECT COUNT(*) FROM TB_RCP_A") == before);
                }

                // 제4.8절: 사용량 임계치. 선택 항목이다.
                if (limit) {
                    if (!"Y".equals(one(con, "SELECT FN_ALLOWED('RRN') FROM DUAL"))) {
                        System.out.println("  [건너뜀] 주민등록번호 복호화 자격이 없어 임계치 확인을 하지 않는다.");
                    } else {
                        int blockedAt = 0;
                        for (int i = 1; i <= 300 && blockedAt == 0; i++) {
                            try {
                                one(con, "SELECT FN_DEC_RRN(mbr_rrn_enc) FROM TB_RCP_A WHERE mbr_id = 1");
                            } catch (SQLException e) {
                                if (e.getErrorCode() == 20522) { blockedAt = i; } else { throw e; }
                            }
                        }
                        check("복호화를 반복하면 ORA-20522 로 막힌다 (" + (blockedAt == 0 ? "막히지 않음" : blockedAt + "번째") + ")",
                                blockedAt > 0 && blockedAt <= 201);
                    }
                }
            } finally {
                con.rollback();
                dropQuietly(con, "DROP PROCEDURE SP_RCP_SAVE");
                dropQuietly(con, "DROP TABLE TB_RCP_B PURGE");
                dropQuietly(con, "DROP TABLE TB_RCP_A PURGE");
                if (!session.release(con)) {
                    System.out.println("  [경고] 문맥을 거두지 못하였다.");
                }
            }
        }
        System.out.println("=== 통과 " + pass + ", 실패 " + fail + " ===");
        System.exit(fail == 0 ? 0 : 1);
    }
}
