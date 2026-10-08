package ocsecure.client;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 개발 모드(APPCTX_MODE=SIMPLE)에서 증표 없이 문맥만 세우는 자바 경로와, 평문 컬럼을
 * 암호문과 색인 컬럼으로 옮기는 데이터 이관 연습을 확인한다.
 *
 * <p>개발자 매뉴얼 제14.2.3절과 제14.2.4절의 호출을 그대로 쓴다. 임시 표 TB_DEVMIG 를 만들고
 * 끝에 지운다. 개발 모드가 꺼져 있으면 문맥을 세우지 못하고 멈춘다. 시험 값은 실제 개인정보가
 * 아닌 일련번호로 만든다.
 *
 * <p>실행. 암호 자리의 하이픈(-)은 화면에 보이지 않게 입력받는다는 뜻이다.
 * <pre>
 *   java -cp out;ojdbc8.jar ocsecure.client.OcsDevModeCheck "jdbc:oracle:thin:@호스트:포트/서비스명" 계정 -
 * </pre>
 */
public final class OcsDevModeCheck {

    private static final int ROWS = 25;
    private static final int BATCH = 10;

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

    private static long count(Connection con, String sql) throws SQLException {
        try (Statement st = con.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private static void ddl(Connection con, String sql) throws SQLException {
        try (Statement st = con.createStatement()) {
            st.execute(sql);
        }
    }

    private static void dropQuietly(Connection con) {
        try {
            ddl(con, "DROP TABLE TB_DEVMIG PURGE");
        } catch (SQLException ignore) {
            // 없으면 그대로 둔다.
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("사용법: OcsDevModeCheck <jdbcUrl> <사용자> <암호|->");
            System.exit(2);
        }
        String pwd = secret(args[2], "응용 계정 암호: ");
        OcsSessionSupport session = new OcsSessionSupport(null);   // 증표 없이 문맥만

        try (Connection con = DriverManager.getConnection(args[0], args[1], pwd)) {
            System.out.println("=== 개발 모드 확인 (증표 없이 문맥만) ===");
            con.setAutoCommit(false);
            try {
                session.establish(con, "개발자1");
            } catch (SQLException e) {
                System.out.println("  문맥을 세우지 못하였다 (ORA-" + e.getErrorCode() + "). 개발 모드가 켜져 있는지 확인할 것.");
                System.exit(2);
            }
            try {
                // 1. 증표 없이도 짧은 이름으로 암호화가 된다.
                try (PreparedStatement ps = con.prepareStatement("SELECT FN_ENC_NAME(?) FROM DUAL")) {
                    ps.setString(1, "홍길동");
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        byte[] c = rs.getBytes(1);
                        check("증표 없이 문맥만 세워도 FN_ENC_NAME 으로 암호화가 된다 (길이 "
                                + (c == null ? "없음" : String.valueOf(c.length)) + ")",
                                c != null && c.length == 68);
                    }
                }

                // 2. 데이터 이관 연습: 평문 컬럼을 암호문과 색인 컬럼으로 옮긴다.
                dropQuietly(con);
                ddl(con, "CREATE TABLE TB_DEVMIG (id NUMBER PRIMARY KEY, rrn_plain VARCHAR2(20),"
                        + " rrn_enc RAW(256), rrn_idx RAW(32))");
                try (PreparedStatement ins = con.prepareStatement(
                        "INSERT INTO TB_DEVMIG (id, rrn_plain) VALUES (?, ?)")) {
                    for (int i = 1; i <= ROWS; i++) {
                        ins.setInt(1, i);
                        ins.setString(2, "9001011" + String.format("%06d", i));
                        ins.executeUpdate();
                    }
                }
                con.commit();
                check("시험 자료 " + ROWS + "건을 평문으로 넣었다",
                        count(con, "SELECT COUNT(*) FROM TB_DEVMIG WHERE rrn_enc IS NULL") == ROWS);

                int batches = 0;
                try (PreparedStatement ps = con.prepareStatement(
                        "UPDATE TB_DEVMIG SET rrn_enc = FN_ENC_RRN(rrn_plain), rrn_idx = FN_IDX_RRN(rrn_plain)"
                        + " WHERE rrn_enc IS NULL AND ROWNUM <= ?")) {
                    ps.setInt(1, BATCH);
                    int n;
                    do {
                        n = ps.executeUpdate();
                        con.commit();
                        if (n > 0) { batches++; }
                    } while (n > 0);
                }
                check("묶음 " + BATCH + "건씩 " + batches + "번에 나누어 모두 옮겼다",
                        batches == 3 && count(con, "SELECT COUNT(*) FROM TB_DEVMIG WHERE rrn_enc IS NULL") == 0);

                check("옮긴 암호문이 모두 68바이트이다",
                        count(con, "SELECT COUNT(*) FROM TB_DEVMIG WHERE UTL_RAW.LENGTH(rrn_enc) <> 68") == 0);

                // 3. 색인으로 한 건을 정확히 찾는다.
                long found;
                try (PreparedStatement ps = con.prepareStatement(
                        "SELECT COUNT(*) FROM TB_DEVMIG WHERE rrn_idx = FN_IDX_RRN(?)")) {
                    ps.setString(1, "9001011" + String.format("%06d", 7));
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        found = rs.getLong(1);
                    }
                }
                check("색인으로 찾으면 정확히 한 건이 나온다 (" + found + "건)", found == 1);
            } finally {
                dropQuietly(con);
                if (!session.release(con)) {
                    System.out.println("  [경고] 문맥을 거두지 못하였다.");
                }
            }

            // 4. 거둔 뒤에는 다시 거부된다.
            try (PreparedStatement ps = con.prepareStatement("SELECT FN_ENC_NAME(?) FROM DUAL")) {
                ps.setString(1, "홍길동");
                ps.executeQuery();
                check("문맥을 거두면 다시 거부된다", false);
            } catch (SQLException e) {
                check("문맥을 거두면 다시 거부된다 (ORA-" + e.getErrorCode() + ")", e.getErrorCode() == 20521);
            }
        }
        System.out.println("=== 통과 " + pass + ", 실패 " + fail + " ===");
        System.exit(fail == 0 ? 0 : 1);
    }
}
