package ocsecure.client;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * 데이터베이스 세션에 애플리케이션 인증 문맥을 세우고 거두는 헬퍼.
 *
 * <p>연결 풀을 쓰는 환경에서 가장 실수하기 쉬운 지점을 다룬다. 문맥은 세션에
 * 붙는 것이지 트랜잭션에 붙는 것이 아니므로, 연결을 빌릴 때마다 세우고 돌려줄 때
 * 반드시 거두어야 한다. 거두지 않고 반납하면 다음에 그 연결을 빌린 다른 사용자가
 * 앞 사람의 문맥을 그대로 물려받는다. 권한이 남의 것으로 판정되는 사고가 여기서
 * 난다.
 *
 * <p>거두는 일은 반드시 finally 에서 한다. 업무 처리가 예외로 끝나도 문맥은 남기지
 * 않아야 한다.
 *
 * <p>JDK 표준 라이브러리만 쓰므로 어느 프레임워크에도 그대로 넣을 수 있다.
 * 전자정부 표준프레임워크에서는 보통 서비스 계층의 시작과 끝에서 호출하거나,
 * 연결을 내어 주는 지점을 감싸서 자동으로 호출되게 한다.
 */
public final class OcsSessionSupport {

    private static final String SQL_SID =
            "SELECT SYS_CONTEXT('USERENV','SID') FROM DUAL";
    private static final String SQL_LOGIN =
            "{ call OCS_OWNER.PKG_SECURE_API.login(?, ?, HEXTORAW(?)) }";
    private static final String SQL_LOGIN_SIMPLE =
            "{ call OCS_OWNER.PKG_SECURE_API.login(?) }";
    private static final String SQL_LOGOUT =
            "{ call OCS_OWNER.PKG_SECURE_API.logout }";

    private final OcsAppProof proof;

    /**
     * @param proof 증표 생성기. null 이면 증표 없이 문맥만 세운다.
     *              증표 없는 방식은 개발과 시험 전용이며, 운영에서 쓰면 이 통제는
     *              사실상 없는 것과 같다.
     */
    public OcsSessionSupport(OcsAppProof proof) {
        this.proof = proof;
    }

    /**
     * 현재 연결에 문맥을 세운다.
     *
     * @param con     업무에 쓸 바로 그 연결. 다른 연결에 세우면 아무 소용이 없다.
     * @param appUser 업무 사용자 식별자. 데이터베이스 계정이 아니라 실제 사용자다.
     */
    public void establish(Connection con, String appUser) throws SQLException {
        if (proof == null) {
            try (CallableStatement cs = con.prepareCall(SQL_LOGIN_SIMPLE)) {
                cs.setString(1, appUser);
                cs.execute();
            }
            return;
        }

        long sid = currentSid(con);
        long epoch = OcsAppProof.nowEpochSeconds();
        try (CallableStatement cs = con.prepareCall(SQL_LOGIN)) {
            cs.setString(1, appUser);
            cs.setLong(2, epoch);
            cs.setString(3, proof.buildHex(appUser, epoch, sid));
            cs.execute();
        }
    }

    /**
     * 문맥을 거둔다. 반드시 finally 에서 호출한다.
     *
     * <p>거두는 데 실패했다고 업무를 되돌릴 수는 없으므로 예외를 삼키되, 조용히
     * 넘기지는 않는다. 호출 쪽에서 로그로 남길 수 있도록 성공 여부를 돌려준다.
     */
    public boolean release(Connection con) {
        try (CallableStatement cs = con.prepareCall(SQL_LOGOUT)) {
            cs.execute();
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    /** 현재 세션의 식별자. 증표에 묶어 다른 세션에서의 재사용을 막는다. */
    public static long currentSid(Connection con) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(SQL_SID);
             ResultSet rs = ps.executeQuery()) {
            if (!rs.next()) {
                throw new SQLException("세션 식별자를 읽지 못하였다");
            }
            return rs.getLong(1);
        }
    }
}
