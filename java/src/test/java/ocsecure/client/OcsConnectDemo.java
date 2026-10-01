package ocsecure.client;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Types;

/**
 * 연동 확인 프로그램.
 *
 * <p>응용 계정으로 접속해서, 증표 키를 가진 쪽에서는 암복호화가 되고 키가 없으면
 * 거부된다는 것을 실제로 확인한다. 업무 코드가 아니라 설치 확인용이다.
 *
 * <p>확인하는 것은 넷이다. 문맥을 세우지 않은 채로는 거부되는가, 증표를 제출하면
 * 암호화가 되는가, 검색용 색인이 같은 평문에 대해 같은 값을 내는가, 복호화 권한이
 * 없으면 암호화는 되어도 복호화는 거부되는가.
 *
 * <p>{@code --data} 를 덧붙이면 투명화 뷰에 실제로 자료를 넣고 꺼내 본다. 08_sample 을
 * 적용한 뒤에 쓴다. 자료를 넣고 꺼내는 일은 조회 도구가 아니라 애플리케이션이 하는
 * 것이므로, 이 확인도 여기서 한다.
 *
 * <p>실행
 * <pre>
 *   javac -cp ojdbc8.jar -d out $(find java/src -name '*.java')
 *   java  -cp out:ojdbc8.jar ocsecure.client.OcsConnectDemo \
 *         "jdbc:oracle:thin:@호스트:포트/SFISPDB949" OCS_APP 암호 &lt;증표키 16진 64자&gt;
 *   java  -cp out:ojdbc8.jar ocsecure.client.OcsConnectDemo ... &lt;증표키&gt; --data
 * </pre>
 *
 * <p>윈도우에서는 클래스패스 구분자가 쌍점이 아니라 쌍반점이다.
 *
 * <p>증표 키를 명령행에 그대로 적으면 명령 이력에 남는다. 확인이 끝나면 이력을
 * 지우는 편이 낫고, 운영 코드에서는 키 관리 제품이나 기동 시점 주입 값에서 읽어야
 * 한다.
 */
public final class OcsConnectDemo {

    private static final String RRN = "8001011234567";

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("사용법: OcsConnectDemo <jdbcUrl> <사용자> <암호> <증표키16진>");
            System.exit(2);
        }
        String url = args[0];
        String user = args[1];
        String pwd = args[2];
        byte[] appCtxKey = OcsCrypto.fromHex(args[3]);
        boolean dataMode = false;
        String appUser = "DEMO_USER";
        for (int i = 4; i < args.length; i++) {
            if ("--data".equals(args[i])) {
                dataMode = true;
            } else {
                appUser = args[i];
            }
        }

        int pass = 0;
        int fail = 0;

        try (Connection con = DriverManager.getConnection(url, user, pwd)) {
            System.out.println("=== OCSecure 연동 확인 ===");
            System.out.println("  접속 성공: " + url);

            // 1. 문맥 없이 시도하면 거부되어야 한다.
            try {
                encRrn(con, RRN);
                fail++;
                System.out.println("  [실패] 문맥 없이 암호화가 되었다. 통제가 새고 있다.");
            } catch (SQLException e) {
                boolean ok = e.getErrorCode() == 20521;
                if (ok) { pass++; } else { fail++; }
                System.out.println("  [" + (ok ? "통과" : "실패")
                        + "] 문맥 없이 암호화하면 거부된다 (ORA-" + e.getErrorCode() + ")");
            }

            // 2. 증표를 제출하고 문맥을 세운다.
            OcsSessionSupport session = new OcsSessionSupport(new OcsAppProof(appCtxKey));
            session.establish(con, appUser);
            System.out.println("  문맥 설정 완료: " + appUser);

            try {
                // 3. 암호화가 된다.
                byte[] c1 = encRrn(con, RRN);
                boolean ok = c1 != null && c1.length == 68;
                if (ok) { pass++; } else { fail++; }
                System.out.println("  [" + (ok ? "통과" : "실패")
                        + "] 증표를 제출하면 암호화가 된다 (길이 "
                        + (c1 == null ? "없음" : String.valueOf(c1.length)) + ")");

                // 4. 같은 평문이라도 암호문은 매번 달라야 한다.
                byte[] c2 = encRrn(con, RRN);
                ok = c2 != null && !OcsCrypto.toHex(c1).equals(OcsCrypto.toHex(c2));
                if (ok) { pass++; } else { fail++; }
                System.out.println("  [" + (ok ? "통과" : "실패")
                        + "] 같은 평문을 두 번 암호화하면 서로 다른 암호문이 된다");

                // 5. 색인은 반대로 매번 같아야 검색이 된다.
                String i1 = idxRrn(con, RRN);
                String i2 = idxRrn(con, "800101-1234567");
                ok = i1 != null && i1.equals(i2);
                if (ok) { pass++; } else { fail++; }
                System.out.println("  [" + (ok ? "통과" : "실패")
                        + "] 구분자가 있든 없든 색인 값이 같다");

                // 6. 복호화는 권한이 따로 있어야 한다. 응용 계정에는 주지 않았으므로
                //    거부되는 것이 정상이다. 열려 있다면 권한 설정을 확인해야 한다.
                try {
                    decRrn(con, c1);
                    fail++;
                    System.out.println("  [실패] 복호화 권한이 없는데 복호화가 되었다.");
                } catch (SQLException e) {
                    ok = e.getErrorCode() == 20520;
                    if (ok) { pass++; } else { fail++; }
                    System.out.println("  [" + (ok ? "통과" : "실패")
                            + "] 복호화 권한이 없으면 거부된다 (ORA-" + e.getErrorCode() + ")");
                }
                if (dataMode) {
                    int[] r = dataChecks(con);
                    pass += r[0];
                    fail += r[1];
                }
            } finally {
                if (!session.release(con)) {
                    System.out.println("  [경고] 문맥을 거두지 못하였다.");
                }
            }
        }

        System.out.println("=== 통과 " + pass + " / 실패 " + fail + " ===");
        if (fail > 0) {
            System.exit(1);
        }
    }

    /**
     * 투명화 뷰에 자료를 넣고 꺼내 본다. 08_sample 을 적용한 뒤에만 쓸 수 있다.
     *
     * <p>복호화 권한이 있으면 평문이, 없으면 마스킹된 값이 나와야 한다. 어느 쪽이
     * 맞는지는 먼저 물어보고 그에 맞추어 판정한다. 권한을 준 뒤에 다시 돌리면
     * 같은 프로그램으로 양쪽을 다 확인할 수 있다.
     */
    private static int[] dataChecks(Connection con) {
        int pass = 0;
        int fail = 0;
        System.out.println("  --- 투명화 뷰 확인 ---");
        try {
            boolean canReveal = "Y".equals(allowed(con, "RRN"));
            System.out.println("  이 세션의 주민등록번호 복호화 자격: "
                    + (canReveal ? "있음" : "없음"));

            exec(con, "DELETE FROM TB_MEMBER WHERE mbr_id IN (9001, 9002)");
            exec(con, "INSERT INTO TB_MEMBER (mbr_id, mbr_name, mbr_rrn, mbr_phone)"
                    + " VALUES (9001, '홍길동', '800101-1234567', '010-1234-5678')");
            exec(con, "INSERT INTO TB_MEMBER (mbr_id, mbr_name, mbr_rrn, mbr_phone)"
                    + " VALUES (9002, '김철수', '751225-1234567', '010-9876-5432')");
            // JDBC 는 기본이 자동 확정이므로 따로 확정하지 않는다.
            System.out.println("  [통과] 평문을 넣으면 트리거가 암호화하여 저장한다");
            pass++;

            String rrn = one(con, "SELECT mbr_rrn FROM TB_MEMBER WHERE mbr_id = 9001");
            boolean plain = "800101-1234567".equals(rrn);
            boolean masked = rrn != null && rrn.indexOf('*') >= 0;
            boolean ok = canReveal ? plain : masked;
            if (ok) { pass++; } else { fail++; }
            System.out.println("  [" + (ok ? "통과" : "실패") + "] 자격에 따라 "
                    + (canReveal ? "평문이" : "마스킹된 값이") + " 나온다  (" + rrn + ")");

            // 마스킹 전용 컬럼은 자격과 무관하게 언제나 가려져 있어야 한다.
            String m = one(con, "SELECT mbr_rrn_masked FROM TB_MEMBER WHERE mbr_id = 9001");
            ok = m != null && m.indexOf('*') >= 0;
            if (ok) { pass++; } else { fail++; }
            System.out.println("  [" + (ok ? "통과" : "실패")
                    + "] 마스킹 전용 컬럼은 자격이 있어도 가려진다  (" + m + ")");

            String a = one(con, "SELECT mbr_id FROM TB_MEMBER WHERE mbr_rrn_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_rrn('800101-1234567')");
            String b = one(con, "SELECT mbr_id FROM TB_MEMBER WHERE mbr_rrn_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_rrn('8001011234567')");
            ok = "9001".equals(a) && "9001".equals(b);
            if (ok) { pass++; } else { fail++; }
            System.out.println("  [" + (ok ? "통과" : "실패")
                    + "] 색인으로 찾으면 구분자와 무관하게 같은 행이 나온다");

            exec(con, "DELETE FROM TB_MEMBER WHERE mbr_id IN (9001, 9002)");
            System.out.println("  시험 자료를 지웠다.");
        } catch (SQLException e) {
            fail++;
            System.out.println("  [실패] 투명화 뷰 확인 중 오류: " + e.getMessage());
        }
        return new int[] { pass, fail };
    }

    private static String allowed(Connection con, String domain) throws SQLException {
        try (CallableStatement cs = con.prepareCall(
                "{ ? = call OCS_OWNER.PKG_SECURE_API.allowed(?) }")) {
            cs.registerOutParameter(1, Types.VARCHAR);
            cs.setString(2, domain);
            cs.execute();
            return cs.getString(1);
        }
    }

    private static void exec(Connection con, String sql) throws SQLException {
        try (java.sql.Statement st = con.createStatement()) {
            st.executeUpdate(sql);
        }
    }

    private static String one(Connection con, String sql) throws SQLException {
        try (java.sql.Statement st = con.createStatement();
             java.sql.ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getString(1) : null;
        }
    }

    private static byte[] encRrn(Connection con, String rrn) throws SQLException {
        try (CallableStatement cs = con.prepareCall(
                "{ ? = call OCS_OWNER.PKG_SECURE_API.enc_rrn(?) }")) {
            cs.registerOutParameter(1, Types.VARBINARY);
            cs.setString(2, rrn);
            cs.execute();
            return cs.getBytes(1);
        }
    }

    private static String idxRrn(Connection con, String rrn) throws SQLException {
        try (CallableStatement cs = con.prepareCall(
                "{ ? = call OCS_OWNER.PKG_SECURE_API.idx_rrn(?) }")) {
            cs.registerOutParameter(1, Types.VARBINARY);
            cs.setString(2, rrn);
            cs.execute();
            byte[] b = cs.getBytes(1);
            return b == null ? null : OcsCrypto.toHex(b);
        }
    }

    private static String decRrn(Connection con, byte[] cipher) throws SQLException {
        try (CallableStatement cs = con.prepareCall(
                "{ ? = call OCS_OWNER.PKG_SECURE_API.dec_rrn(?) }")) {
            cs.registerOutParameter(1, Types.VARCHAR);
            cs.setBytes(2, cipher);
            cs.execute();
            return cs.getString(1);
        }
    }
}
