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
 * <p>실행
 * <pre>
 *   javac -cp ojdbc8.jar -d out $(find java/src -name '*.java')
 *   java  -cp out:ojdbc8.jar ocsecure.client.OcsConnectDemo \
 *         "jdbc:oracle:thin:@호스트:포트/SFISPDB949" OCS_APP 암호 &lt;증표키 16진 64자&gt;
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
        String appUser = args.length > 4 ? args[4] : "DEMO_USER";

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
