package ocsecure.example;

import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;

import ocsecure.client.OcsSessionSupport;

/**
 * DB 연결을 얻고, 세션을 등록하고, 업무를 하고, 등록을 해제하고, 연결을 닫는 일을 한곳에 모은 도우미.
 *
 * <p>서비스마다 try/finally 를 반복하지 않도록 이 한 곳에서만 세션 등록을 다룬다. 업무 코드는 넘겨받은
 * 연결 하나로 모든 조회와 갱신을 하며, 같은 트랜잭션 안에서 다른 연결을 쓰지 않는다.
 *
 * <p>사용 예.
 * <pre>
 *   OcsWork work = new OcsWork(dataSource, session);
 *   int n = work.run("member.admin", con -> MemberExample.insertMember(con, 1L, "홍길동", "880101-1234567", "010-1234-5678", "Pw#12345"));
 * </pre>
 */
public final class OcsWork {

    /** 연결 하나로 하는 업무. */
    public interface Task<T> {
        T run(Connection con) throws SQLException;
    }

    private final DataSource dataSource;
    private final OcsSessionSupport session;

    public OcsWork(DataSource dataSource, OcsSessionSupport session) {
        this.dataSource = dataSource;
        this.session = session;
    }

    public <T> T run(String appUser, Task<T> task) throws SQLException {
        try (Connection con = dataSource.getConnection()) {
            con.setAutoCommit(false);
            session.establish(con, appUser);
            try {
                T result = task.run(con);
                con.commit();
                return result;
            } catch (SQLException | RuntimeException e) {
                // 삼키지 않는다. 되돌리고 다시 던진다.
                con.rollback();
                throw e;
            } finally {
                // 연결을 닫기 전에 반드시 등록을 해제한다. 해제하지 않으면 풀의 다음 사용자가 앞 사용자의 등록을 이어받는다.
                if (!session.release(con)) {
                    System.err.println("세션 등록을 해제하지 못하였다. 이 연결은 풀로 돌려보내지 말고 닫는 편이 안전하다.");
                }
            }
        }
    }
}
