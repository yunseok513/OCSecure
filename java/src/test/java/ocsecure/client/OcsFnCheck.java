package ocsecure.client;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * 짧은 함수 이름(FN_)을 증표를 제출한 응용 세션에서 부르는 경로를 확인한다.
 *
 * <p>OcsConnectDemo 는 패키지 이름을 붙인 긴 호출로 확인한다. 이 프로그램은 같은 접속에서
 * 업무 계정의 시노님으로 FN_ 함수를 부르며, 쿼리 안에서 쓰는 모양 그대로이다. 시험 자료는
 * 만들지 않는다. 암호화한 값은 메모리에서만 쓰고 저장하지 않는다.
 *
 * <p>실행. 암호와 증표 키 자리의 하이픈(-)은 화면에 보이지 않게 입력받는다는 뜻이다.
 * <pre>
 *   java -cp out;ojdbc8.jar ocsecure.client.OcsFnCheck "jdbc:oracle:thin:@호스트:포트/서비스명" 계정 - -
 * </pre>
 */
public final class OcsFnCheck {

    private static final String NAME = "홍길동";

    private static int pass = 0;
    private static int fail = 0;

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

    private static void check(String what, boolean ok) {
        if (ok) { pass++; } else { fail++; }
        System.out.println("  [" + (ok ? "통과" : "실패") + "] " + what);
    }

    /** 결과 한 값을 문자열로 읽는다. RAW 는 16진으로 바꾼다. */
    private static String one(Connection con, String sql, Object... binds) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            for (int i = 0; i < binds.length; i++) {
                if (binds[i] instanceof byte[]) {
                    ps.setBytes(i + 1, (byte[]) binds[i]);
                } else {
                    ps.setString(i + 1, (String) binds[i]);
                }
            }
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                Object o = rs.getObject(1);
                if (o instanceof byte[]) {
                    return OcsCrypto.toHex((byte[]) o);
                }
                return o == null ? null : o.toString();
            }
        }
    }

    private static byte[] raw(Connection con, String sql, String bind) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, bind);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getBytes(1) : null;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("사용법: OcsFnCheck <jdbcUrl> <사용자> <암호|-> <증표키16진|->");
            System.exit(2);
        }
        String pwd = secret(args[2], "응용 계정 암호: ");
        String keyHex = secret(args[3], "증표 키(16진 64자): ").trim();
        if (!keyHex.matches("[0-9A-Fa-f]{64}")) {
            System.out.println("증표 키가 올바르지 않다. 16진 64자여야 한다. 입력된 길이: " + keyHex.length() + "자");
            System.exit(2);
        }
        OcsSessionSupport session = new OcsSessionSupport(new OcsAppProof(OcsCrypto.fromHex(keyHex)));

        try (Connection con = DriverManager.getConnection(args[0], args[1], pwd)) {
            System.out.println("=== FN_ 짧은 이름 확인 (증표 제출 세션) ===");

            // 1. 문맥 없이 부르면 거부된다. 시노님이 풀려 패키지까지 도달했다는 뜻이기도 하다.
            try {
                one(con, "SELECT FN_ENC_NAME(?) FROM DUAL", NAME);
                check("문맥 없이 FN_ENC_NAME 을 부르면 거부된다", false);
            } catch (SQLException e) {
                check("문맥 없이 FN_ENC_NAME 을 부르면 거부된다 (ORA-" + e.getErrorCode() + ")",
                        e.getErrorCode() == 20521);
            }

            session.establish(con, "FN_CHECK");
            try {
                // 2. 증표를 제출한 뒤에는 짧은 이름으로 암호화가 된다.
                byte[] c1 = raw(con, "SELECT FN_ENC_NAME(?) FROM DUAL", NAME);
                check("문맥을 세우면 FN_ENC_NAME 으로 암호화가 된다 (길이 "
                        + (c1 == null ? "없음" : String.valueOf(c1.length)) + ")",
                        c1 != null && c1.length == 68);

                // 3. 색인은 같은 평문이면 같은 값이다.
                String i1 = one(con, "SELECT FN_IDX_NAME(?) FROM DUAL", NAME);
                String i2 = one(con, "SELECT FN_IDX_NAME(?) FROM DUAL", NAME);
                check("FN_IDX_NAME 은 같은 평문에 같은 값을 낸다",
                        i1 != null && i1.length() == 64 && i1.equals(i2));

                // 4. 마스킹은 자격 없이 되고 평문과 다르다.
                String masked = one(con, "SELECT FN_MASKED('NAME', ?) FROM DUAL", c1);
                check("FN_MASKED 는 마스킹된 값을 낸다 (" + masked + ")",
                        masked != null && !masked.equals(NAME));

                // 5. 복호화 자격은 따로 물어보고 그에 맞추어 판정한다.
                boolean can = "Y".equals(one(con, "SELECT FN_ALLOWED('NAME') FROM DUAL"));
                System.out.println("  복호화 자격(성명): " + (can ? "있음" : "없음"));
                try {
                    String back = one(con, "SELECT FN_DEC_NAME(?) FROM DUAL", c1);
                    check("자격이 " + (can ? "있으므로 FN_DEC_NAME 이 평문을 낸다" : "없는데 FN_DEC_NAME 이 되었다"),
                            can && NAME.equals(back));
                } catch (SQLException e) {
                    check("자격이 없으면 FN_DEC_NAME 이 거부된다 (ORA-" + e.getErrorCode() + ")",
                            !can && e.getErrorCode() == 20520);
                }

                // 6. FN_SHOW 는 자격이 있으면 평문, 없으면 마스킹 값을 낸다.
                String shown = one(con, "SELECT FN_SHOW('NAME', ?) FROM DUAL", c1);
                check("FN_SHOW 는 자격에 따라 " + (can ? "평문" : "마스킹 값") + "을 낸다",
                        can ? NAME.equals(shown) : (shown != null && shown.equals(masked)));
            } finally {
                if (!session.release(con)) {
                    System.out.println("  [경고] 문맥을 거두지 못하였다.");
                }
            }

            // 7. 거둔 뒤에는 다시 거부된다.
            try {
                one(con, "SELECT FN_ENC_NAME(?) FROM DUAL", NAME);
                check("문맥을 거두면 다시 거부된다", false);
            } catch (SQLException e) {
                check("문맥을 거두면 다시 거부된다 (ORA-" + e.getErrorCode() + ")",
                        e.getErrorCode() == 20521);
            }
        }
        System.out.println("=== 통과 " + pass + ", 실패 " + fail + " ===");
        System.exit(fail == 0 ? 0 : 1);
    }
}
