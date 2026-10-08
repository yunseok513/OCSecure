package ocsecure.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import ocsecure.client.OcsAppProof;
import ocsecure.client.OcsCrypto;
import ocsecure.client.OcsSessionSupport;

/**
 * 개발자 매뉴얼 제3장의 예제. 연결을 얻고, 문맥을 세우고, 저장하고, 읽고, 찾고, 고치고,
 * 지우고, 문맥을 거두는 흐름을 한 파일에 담았다.
 *
 * <p>전제. 업무 계정에 sql/08_sample/800_sample_member.sql 로 TB_MEMBER 가 만들어져 있어야 한다.
 * 이 예제는 TB_MEMBER 의 투명화 뷰와 원본 표 TB_MEMBER_ENC 를 쓴다. 값은 모두 시험용으로 만든
 * 값이며 실제 개인정보가 아니다.
 *
 * <p>실행. 암호와 증표 키 자리의 하이픈(-)은 화면에 보이지 않게 입력받는다는 뜻이다.
 * <pre>
 *   java -cp out;ojdbc8.jar ocsecure.example.MemberExample "jdbc:oracle:thin:@호스트:포트/서비스명" 계정 - -
 * </pre>
 *
 * <p>실제 응용에서는 DriverManager 대신 연결 풀(DataSource)에서 연결을 빌리고, 증표 키는
 * 키 관리 제품이나 기동 시점에 주입되는 값에서 읽는다. 문맥을 세우고 거두는 부분(establish,
 * release)이 이 예제의 핵심이다.
 */
public final class MemberExample {

    private static final long ID = 9301L;

    private static String secret(String arg, String prompt) {
        if (!"-".equals(arg)) {
            return arg;
        }
        java.io.Console c = System.console();
        if (c == null) {
            throw new IllegalStateException("콘솔이 없어 비밀값을 입력받을 수 없다. 명령 프롬프트에서 실행하라.");
        }
        return new String(c.readPassword("%s", prompt));
    }

    /** 가입. 뷰에 평문을 넣으면 트리거가 암호화와 색인 생성을 대신한다. 비밀번호는 전용 함수로 만든다. */
    static int insertMember(Connection con, long id, String name, String rrn, String phone, String pwd)
            throws SQLException {
        String sql = "INSERT INTO TB_MEMBER (mbr_id, mbr_name, mbr_rrn, mbr_phone, mbr_pwd)"
                   + " VALUES (?, ?, ?, ?, FN_MAKE_PWD(?))";
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setLong(1, id);
            ps.setString(2, name);
            ps.setString(3, rrn);
            ps.setString(4, phone);
            ps.setString(5, pwd);
            return ps.executeUpdate();
        }
    }

    /** 상세. 평문 컬럼은 복호화 자격이 있으면 평문, 없으면 마스킹 값이다. 오류가 아니다. */
    static void printDetail(Connection con, long id) throws SQLException {
        String sql = "SELECT mbr_name, mbr_rrn, mbr_phone FROM TB_MEMBER WHERE mbr_id = ?";
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    System.out.println("  상세  성명=" + rs.getString(1) + "  주민등록번호=" + rs.getString(2)
                            + "  연락처=" + rs.getString(3));
                }
            }
        }
    }

    /** 목록. 안쪽에서 먼저 자르고 바깥에서 마스킹 함수를 건다. 행마다 복호화하지 않는다. */
    static void printList(Connection con, int first, int size) throws SQLException {
        String sql = "SELECT t.mbr_id, FN_MASKED('RRN', t.mbr_rrn_enc) AS rrn_masked"
                   + "  FROM (SELECT mbr_id, mbr_rrn_enc FROM TB_MEMBER_ENC"
                   + "         ORDER BY mbr_id OFFSET ? ROWS FETCH NEXT ? ROWS ONLY) t"
                   + " ORDER BY t.mbr_id";
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setInt(1, first);
            ps.setInt(2, size);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    System.out.println("  목록  번호=" + rs.getLong(1) + "  주민등록번호=" + rs.getString(2));
                }
            }
        }
    }

    /** 검색. 암호화 컬럼이 아니라 색인 컬럼으로 찾는다. 구분자가 있든 없든 같은 행이 나온다. */
    static int countByRrn(Connection con, String rrn) throws SQLException {
        String sql = "SELECT COUNT(*) FROM TB_MEMBER_ENC WHERE mbr_rrn_idx = FN_IDX_RRN(?)";
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, rrn);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    /** 수정. 바뀐 컬럼만 트리거가 다시 암호화한다. */
    static int updatePhone(Connection con, long id, String phone) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement("UPDATE TB_MEMBER SET mbr_phone = ? WHERE mbr_id = ?")) {
            ps.setString(1, phone);
            ps.setLong(2, id);
            return ps.executeUpdate();
        }
    }

    /** 로그인 검증. 1 일치, 0 불일치, 조회 결과 없음은 없는 사용자. */
    static int checkPassword(Connection con, long id, String input) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "SELECT FN_VERIFY_PWD(?, mbr_pwd) FROM TB_MEMBER_ENC WHERE mbr_id = ?")) {
            ps.setString(1, input);
            ps.setLong(2, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : -1;
            }
        }
    }

    static int delete(Connection con, long id) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement("DELETE FROM TB_MEMBER WHERE mbr_id = ?")) {
            ps.setLong(1, id);
            return ps.executeUpdate();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("사용법: MemberExample <jdbcUrl> <사용자> <암호|-> <증표키16진|->");
            System.exit(2);
        }
        String pwd = secret(args[2], "응용 계정 암호: ");
        String keyHex = secret(args[3], "증표 키(16진 64자): ").trim();

        // 기동 시 한 번 만든다.
        OcsSessionSupport session = new OcsSessionSupport(new OcsAppProof(OcsCrypto.fromHex(keyHex)));

        try (Connection con = DriverManager.getConnection(args[0], args[1], pwd)) {
            con.setAutoCommit(false);
            // 연결을 빌릴 때마다 문맥을 세운다. 업무 사용자 식별자는 데이터베이스 계정이 아니라 실제 사용자다.
            session.establish(con, "member.admin");
            try {
                delete(con, ID);   // 이전 실행이 남긴 자료가 있으면 지운다.

                System.out.println("  가입  " + insertMember(con, ID, "홍길동", "880101-1234567", "010-1234-5678", "Pw#12345") + "건");
                con.commit();

                printDetail(con, ID);
                printList(con, 0, 10);

                System.out.println("  검색  구분자 있음=" + countByRrn(con, "880101-1234567")
                        + "건  구분자 없음=" + countByRrn(con, "8801011234567") + "건");

                System.out.println("  수정  " + updatePhone(con, ID, "010-9999-8888") + "건");
                con.commit();

                System.out.println("  비밀번호  맞는 값=" + checkPassword(con, ID, "Pw#12345")
                        + "  틀린 값=" + checkPassword(con, ID, "wrong") + "  없는 사용자=" + checkPassword(con, ID + 1, "x"));

                System.out.println("  삭제  " + delete(con, ID) + "건");
                con.commit();
            } catch (SQLException e) {
                // 삼키지 않는다. 되돌리고 다시 던진다.
                con.rollback();
                throw e;
            } finally {
                // 반납 전에 반드시 거둔다. 거두지 않으면 풀의 다음 사용자가 이 문맥을 물려받는다.
                if (!session.release(con)) {
                    System.out.println("  [경고] 문맥을 거두지 못하였다.");
                }
            }
        }
    }
}
