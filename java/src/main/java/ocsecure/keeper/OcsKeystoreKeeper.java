package ocsecure.keeper;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.Set;

/**
 * 키 저장소 유지 프로그램.
 *
 * <p>오라클의 전역 문맥에 넣은 값은 그 값을 넣은 세션이 살아 있는 동안만 유지된다.
 * 마스터 키를 전역 문맥으로 반입하는 구성에서는 따라서 누군가 연결 하나를 계속
 * 붙들고 있어야 한다. 그 일만 하는 것이 이 프로그램이다. 사람이 띄워 둔 창에
 * 시스템이 매달리는 상태를 없애는 것이 목적이다.
 *
 * <p>하는 일은 넷뿐이다. 설정에서 마스터 키를 읽고, 키 관리 계정으로 접속하여
 * 주입하고, 주기적으로 저장소가 열려 있는지 확인하고, 끊기거나 닫혀 있으면 다시
 * 붙어 다시 주입한다. 업무 처리는 하지 않으며 자료를 읽지도 쓰지도 않는다.
 *
 * <p>데이터베이스를 재기동하면 전역 문맥이 비워지므로, 이 프로그램이 다시 붙어
 * 주입할 때까지 암복호화가 멈춘다. 확인 주기를 짧게 둘수록 그 공백이 줄어든다.
 *
 * <p>설정 파일 예시다. 이 파일에는 마스터 키와 계정 암호가 들어가므로 운영체제
 * 권한으로 보호해야 한다. 리눅스에서는 소유자만 읽을 수 있게 두고(chmod 600),
 * 윈도우에서는 해당 서비스 계정만 읽도록 접근 제어를 건다.
 *
 * <pre>
 *   jdbc.url=jdbc:oracle:thin:@호스트:1521/SFISPDB949
 *   jdbc.user=OCS_KEYADM
 *   jdbc.password=...
 *   master.key=&lt;16진 64자&gt;
 *   check.seconds=30
 * </pre>
 *
 * <p>실행
 * <pre>
 *   java -cp ocsecure-client.jar;ojdbc8.jar ocsecure.keeper.OcsKeystoreKeeper keeper.properties
 *   java -cp ... ocsecure.keeper.OcsKeystoreKeeper keeper.properties --once
 * </pre>
 *
 * <p>{@code --once} 는 한 번 주입하고 확인한 뒤 끝낸다. 설정이 맞는지 보는 데 쓴다.
 * 평소에는 인자 없이 띄워 서비스나 데몬으로 돌린다.
 */
public final class OcsKeystoreKeeper {

    private static final String SQL_SET =
            "{ call OCS_OWNER.PKG_KEK_PROVIDER.set_master_key(HEXTORAW(?)) }";
    // 열려 있는지는 전역 문맥으로 판정한다. PKG_KEK_PROVIDER.is_open 은 세션이 담아 둔
    // 값을 보므로, 다른 세션이 저장소를 닫아 전역 문맥이 비워져도 이 프로그램의 세션에는
    // 계속 열림으로 보인다. 그러면 닫힌 것을 알아채지 못한다. 키 값은 읽지 않고 있는지만
    // 묻는다. 문맥에 값이 있을 때만 세션 상태도 함께 확인한다.
    private static final String SQL_IS_OPEN =
            "BEGIN ? := CASE WHEN SYS_CONTEXT('OCS_KEK_CTX', 'MASTER') IS NOT NULL"
            + " AND OCS_OWNER.PKG_KEK_PROVIDER.is_open THEN 1 ELSE 0 END; END;";
    private static final String SQL_PING = "SELECT 1 FROM DUAL";

    private static final SimpleDateFormat STAMP =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private final String url;
    private final String user;
    private final String password;
    private final String masterKeyHex;
    private final long checkMillis;

    private Connection con;

    private OcsKeystoreKeeper(Properties p) {
        this.url = need(p, "jdbc.url");
        this.user = need(p, "jdbc.user");
        this.password = need(p, "jdbc.password");
        this.masterKeyHex = need(p, "master.key").trim();
        if (masterKeyHex.length() < 64) {
            throw new IllegalArgumentException(
                    "master.key 는 16진 64자 이상이어야 한다 (현재 " + masterKeyHex.length() + "자)");
        }
        long sec = Long.parseLong(p.getProperty("check.seconds", "30"));
        if (sec < 5) {
            throw new IllegalArgumentException("check.seconds 는 5 이상이어야 한다");
        }
        this.checkMillis = sec * 1000L;
    }

    private static String need(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.trim().isEmpty()) {
            throw new IllegalArgumentException("설정 항목이 비어 있다: " + key);
        }
        return v.trim();
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("사용법: OcsKeystoreKeeper <설정파일> [--once]");
            System.exit(2);
        }
        boolean once = args.length > 1 && "--once".equals(args[1]);

        Properties p = new Properties();
        File f = new File(args[0]);
        warnIfReadableByOthers(f);
        try (InputStream in = new FileInputStream(f)) {
            p.load(in);
        } catch (Exception e) {
            log("설정 파일을 읽지 못하였다: " + e.getMessage());
            System.exit(2);
        }

        OcsKeystoreKeeper keeper;
        try {
            keeper = new OcsKeystoreKeeper(p);
        } catch (RuntimeException e) {
            log("설정이 올바르지 않다: " + e.getMessage());
            System.exit(2);
            return;
        }

        if (once) {
            System.exit(keeper.runOnce() ? 0 : 1);
        }
        keeper.runForever();
    }

    /** 한 번 주입하고 확인한 뒤 끝낸다. 설정 점검용이다. */
    private boolean runOnce() {
        try {
            connectAndInject();
            boolean open = isOpen();
            log(open ? "저장소가 열렸다. 설정이 올바르다." : "주입했으나 열려 있지 않다. 확인이 필요하다.");
            return open;
        } catch (SQLException e) {
            log("실패: " + e.getMessage());
            return false;
        } finally {
            closeQuietly();
        }
    }

    private void runForever() {
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                log("종료한다. 이 시점부터 암복호화가 멈춘다.");
                closeQuietly();
            }
        });

        log("시작한다. 확인 주기 " + (checkMillis / 1000) + "초.");
        boolean healthy = false;

        while (true) {
            try {
                if (con == null || con.isClosed()) {
                    connectAndInject();
                    log("접속하고 마스터 키를 주입하였다.");
                    healthy = true;
                } else {
                    ping();
                    if (!isOpen()) {
                        // 누군가 닫았거나 데이터베이스가 재기동되었다.
                        log("저장소가 닫혀 있다. 다시 주입한다.");
                        inject();
                        healthy = true;
                    } else if (!healthy) {
                        log("정상으로 돌아왔다.");
                        healthy = true;
                    }
                }
            } catch (SQLException e) {
                if (healthy) {
                    // 상태가 바뀔 때만 남긴다. 같은 오류를 주기마다 쌓지 않는다.
                    log("끊겼다. 다시 붙기를 되풀이한다: " + e.getMessage());
                }
                healthy = false;
                closeQuietly();
            }

            try {
                Thread.sleep(checkMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void connectAndInject() throws SQLException {
        con = DriverManager.getConnection(url, user, password);
        con.setAutoCommit(true);
        inject();
    }

    private void inject() throws SQLException {
        try (CallableStatement cs = con.prepareCall(SQL_SET)) {
            cs.setString(1, masterKeyHex);
            cs.execute();
        }
    }

    private boolean isOpen() throws SQLException {
        try (CallableStatement cs = con.prepareCall(SQL_IS_OPEN)) {
            cs.registerOutParameter(1, Types.INTEGER);
            cs.execute();
            return cs.getInt(1) == 1;
        }
    }

    private void ping() throws SQLException {
        try (Statement st = con.createStatement()) {
            st.executeQuery(SQL_PING).close();
        }
    }

    private void closeQuietly() {
        if (con != null) {
            try {
                con.close();
            } catch (SQLException ignored) {
                // 닫는 데 실패해도 할 수 있는 일이 없다.
            }
            con = null;
        }
    }

    /**
     * 설정 파일이 남에게도 읽히면 알린다. 이 파일에는 마스터 키가 들어 있다.
     * 윈도우에서는 이 방식으로 확인되지 않으므로 접근 제어를 따로 확인해야 한다.
     */
    private static void warnIfReadableByOthers(File f) {
        try {
            Set<PosixFilePermission> perms =
                    Files.getPosixFilePermissions(f.toPath());
            if (perms.contains(PosixFilePermission.GROUP_READ)
                    || perms.contains(PosixFilePermission.OTHERS_READ)) {
                log("[경고] 설정 파일을 소유자 외에도 읽을 수 있다. chmod 600 으로 막을 것.");
            }
        } catch (Exception ignored) {
            // 윈도우 등 POSIX 권한이 없는 환경이다. 여기서는 확인하지 않는다.
        }
    }

    private static void log(String msg) {
        System.out.println(STAMP.format(new Date()) + "  " + msg);
    }
}
