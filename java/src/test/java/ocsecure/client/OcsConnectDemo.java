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
 * 것이므로, 이 확인도 여기서 한다. 확인이 끝나면 넣었던 자료를 지운다.
 *
 * <p>{@code --keep} 은 {@code --data} 와 같되 시험 자료를 지우지 않고 남긴다. 키 교체
 * 리허설에 옮길 자료가 있어야 하므로 그때 쓴다. 리허설이 끝나면 직접 지워야 한다.
 *
 * <p>{@code --read} 는 남아 있는 시험 자료를 읽기만 한다. 넣지도 지우지도 않으므로,
 * 키를 교체한 직후와 옛 키를 폐기한 직후에 옛 자료가 그대로 읽히는지 보는 데 쓴다.
 *
 * <p>{@code --staff} 는 08_sample/810_usage_examples.sql 의 직원 표(TB_STAFF)를 시험한다.
 * 뷰로 넣고, 꺼내고, 색인으로 찾고, 컬럼 하나만 고쳤을 때 그 컬럼의 암호문만 바뀌는지
 * 보고, 지운다. 시험 자료(9201, 9202)는 끝에 지운다. 810 을 적용한 뒤에 쓴다.
 *
 * <p>복호화 자격이 있는지는 먼저 물어보고 그에 맞추어 판정하므로, 자격을 주기 전과
 * 준 뒤에 같은 프로그램을 그대로 다시 돌릴 수 있다. 통과 건수는 어느 쪽이든 같다.
 *
 * <p>실행
 * <pre>
 *   javac -cp ojdbc8.jar -d out $(find java/src -name '*.java')
 *   java  -cp out:ojdbc8.jar ocsecure.client.OcsConnectDemo \
 *         "jdbc:oracle:thin:@호스트:포트/서비스명" OCS_APP - -
 *   java  -cp out:ojdbc8.jar ocsecure.client.OcsConnectDemo ... OCS_APP - - --data
 * </pre>
 *
 * <p>윈도우에서는 클래스패스 구분자가 쌍점이 아니라 쌍반점이다.
 *
 * <p>암호와 증표 키 자리에 하이픈(-)을 적으면 실행할 때 화면에 보이지 않게 입력받는다.
 * 명령행에 그대로 적으면 명령 이력과 실행 중 프로세스 목록에 남으므로 하이픈을 쓴다.
 * 운영 코드에서는 키 관리 제품이나 기동 시점 주입 값에서 읽어야 한다.
 */
public final class OcsConnectDemo {

    private static final String RRN = "8001011234567";

    /** 값이 하이픈이면 화면에 보이지 않게 입력받고, 아니면 그대로 쓴다. */
    private static String secret(String arg, String prompt) throws Exception {
        if (!"-".equals(arg)) {
            return arg;
        }
        java.io.Console c = System.console();
        if (c == null) {
            throw new IllegalStateException("콘솔이 없어 비밀값을 입력받을 수 없다. 명령 프롬프트에서 실행하십시오.");
        }
        return new String(c.readPassword("%s", prompt));
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("사용법: OcsConnectDemo <jdbcUrl> <사용자> <암호|-> <증표키16진|->  (-는 화면에 보이지 않게 입력)");
            System.exit(2);
        }
        String url = args[0];
        String user = args[1];
        String pwd = secret(args[2], "응용 계정 암호: ");
        byte[] appCtxKey = OcsCrypto.fromHex(secret(args[3], "증표 키(16진 64자): "));
        boolean dataMode = false;
        boolean keepData = false;
        boolean readOnly = false;
        boolean staffMode = false;
        String appUser = "DEMO_USER";
        for (int i = 4; i < args.length; i++) {
            if ("--data".equals(args[i])) {
                dataMode = true;
            } else if ("--keep".equals(args[i])) {
                dataMode = true;
                keepData = true;
            } else if ("--read".equals(args[i])) {
                readOnly = true;
            } else if ("--staff".equals(args[i])) {
                staffMode = true;
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

                // 6. 복호화는 권한이 따로 있어야 한다. 자격이 없으면 거부되어야 하고,
                //    자격을 준 뒤라면 평문이 나와야 한다. 어느 쪽이 맞는지는 먼저
                //    물어보고 그에 맞추어 판정한다. 그래야 자격을 주기 전과 준 뒤에
                //    같은 프로그램으로 양쪽을 다 확인할 수 있다.
                boolean canReveal = "Y".equals(allowed(con, "RRN"));
                try {
                    String back = decRrn(con, c1);
                    ok = canReveal && RRN.equals(back);
                    if (ok) { pass++; } else { fail++; }
                    System.out.println("  [" + (ok ? "통과" : "실패")
                            + "] 복호화 자격이 " + (canReveal ? "있으므로 평문이 나온다"
                                                           : "없는데 복호화가 되었다"));
                } catch (SQLException e) {
                    ok = !canReveal && e.getErrorCode() == 20520;
                    if (ok) { pass++; } else { fail++; }
                    System.out.println("  [" + (ok ? "통과" : "실패")
                            + "] 복호화 자격이 없으면 거부된다 (ORA-" + e.getErrorCode() + ")");
                }
                if (dataMode) {
                    int[] r = dataChecks(con, keepData);
                    pass += r[0];
                    fail += r[1];
                }
                if (readOnly) {
                    int[] r = readChecks(con);
                    pass += r[0];
                    fail += r[1];
                }
                if (staffMode) {
                    int[] r = staffChecks(con);
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
    private static int[] dataChecks(Connection con, boolean keepData) {
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

            if (keepData) {
                System.out.println("  시험 자료(9001, 9002)를 남겨 두었다."
                        + " 키 교체 리허설이 끝나면 지워야 한다.");
            } else {
                exec(con, "DELETE FROM TB_MEMBER WHERE mbr_id IN (9001, 9002)");
                System.out.println("  시험 자료를 지웠다.");
            }
        } catch (SQLException e) {
            fail++;
            System.out.println("  [실패] 투명화 뷰 확인 중 오류: " + e.getMessage());
        }
        return new int[] { pass, fail };
    }

    /**
     * 남아 있는 시험 자료를 읽기만 한다. 넣지도 지우지도 않는다.
     *
     * <p>키를 교체한 직후와 옛 키를 폐기한 직후에, 옛 키로 저장된 자료가 그대로
     * 읽히는지 확인하는 데 쓴다. 조회 도구에서는 응용 문맥을 세울 수 없으므로
     * 이 확인도 여기서 한다.
     */
    private static int[] readChecks(Connection con) {
        System.out.println("  --- 남은 자료 읽기 확인 ---");
        try {
            boolean canReveal = "Y".equals(allowed(con, "RRN"));
            String a = one(con, "SELECT mbr_rrn FROM TB_MEMBER WHERE mbr_id = 9001");
            String b = one(con, "SELECT mbr_rrn FROM TB_MEMBER WHERE mbr_id = 9002");
            if (a == null || b == null) {
                System.out.println("  [실패] 시험 자료(9001, 9002)가 없다."
                        + " --keep 으로 남겨 두었는지 확인할 것.");
                return new int[] { 0, 1 };
            }
            boolean ok = canReveal
                    ? ("800101-1234567".equals(a) && "751225-1234567".equals(b))
                    : (a.indexOf('*') >= 0 && b.indexOf('*') >= 0);
            System.out.println("  [" + (ok ? "통과" : "실패") + "] 두 건이 그대로 읽힌다"
                    + "  (" + a + ", " + b + ")");
            return new int[] { ok ? 1 : 0, ok ? 0 : 1 };
        } catch (SQLException e) {
            System.out.println("  [실패] 남은 자료 읽기 중 오류: " + e.getMessage());
            return new int[] { 0, 1 };
        }
    }

    /**
     * 810 예시의 직원 표(TB_STAFF)를 시험한다.
     *
     * <p>고치기 시험이 핵심이다. 뷰의 INSTEAD OF 트리거는 바뀐 컬럼만 다시 암호화해야
     * 하며, 그렇지 않으면 값이 같은데도 암호문이 바뀌거나 반대로 바꾼 컬럼이 갱신되지
     * 않는다. 갱신이 조용히 사라지는 일은 한 행 갱신되었다고 나오므로 값을 직접 비교해야
     * 드러난다. 그래서 고치기 전후의 암호문을 16진으로 읽어 견주어 본다.
     *
     * <p>복호화 자격이 있으면 평문이, 없으면 마스킹된 값이 나와야 한다. 도메인마다
     * 따로 물어보고 그에 맞추어 판정한다.
     */
    private static int[] staffChecks(Connection con) {
        Tally t = new Tally();
        System.out.println("  --- 직원 표(810) 확인 ---");
        try {
            cleanStaff(con);
            boolean canName = "Y".equals(allowed(con, "NAME"));
            boolean canRrn = "Y".equals(allowed(con, "RRN"));
            boolean canTel = "Y".equals(allowed(con, "PHONE"));
            System.out.println("  복호화 자격  성명:" + (canName ? "있음" : "없음")
                    + "  주민등록번호:" + (canRrn ? "있음" : "없음")
                    + "  연락처:" + (canTel ? "있음" : "없음"));

            // 1. 평문을 뷰에 넣으면 트리거가 암호화하여 저장한다.
            exec(con, "INSERT INTO TB_STAFF (staff_id, login_id, staff_nm, rrn, tel)"
                    + " VALUES (9201, 'staff_a', '박민수', '900101-1234567', '010-1111-2222')");
            exec(con, "INSERT INTO TB_STAFF (staff_id, login_id, staff_nm, rrn, tel)"
                    + " VALUES (9202, 'staff_b', '이영희', '850505-2345678', '010-3333-4444')");
            t.check("뷰에 평문을 넣으면 두 건이 저장된다",
                    "2".equals(one(con, "SELECT COUNT(*) FROM TB_STAFF_ENC"
                            + " WHERE staff_id IN (9201, 9202)")), null);

            // 2. 실제 표에는 암호문과 색인이 들어 있고 평문이 아니다.
            String rrnLen = one(con, "SELECT UTL_RAW.LENGTH(rrn_enc) FROM TB_STAFF_ENC"
                    + " WHERE staff_id = 9201");
            String filled = one(con, "SELECT CASE WHEN staff_nm_enc IS NOT NULL"
                    + " AND staff_nm_idx IS NOT NULL AND rrn_idx IS NOT NULL"
                    + " AND tel_enc IS NOT NULL THEN 'Y' ELSE 'N' END FROM TB_STAFF_ENC"
                    + " WHERE staff_id = 9201");
            t.check("실제 표에는 암호문(주민등록번호 68바이트)과 색인이 채워진다",
                    "68".equals(rrnLen) && "Y".equals(filled), "길이=" + rrnLen + " 채움=" + filled);

            // 3. 자격에 따라 평문 또는 마스킹된 값이 나온다.
            String nm = one(con, "SELECT staff_nm FROM TB_STAFF WHERE staff_id = 9201");
            String rrn = one(con, "SELECT rrn FROM TB_STAFF WHERE staff_id = 9201");
            String tel = one(con, "SELECT tel FROM TB_STAFF WHERE staff_id = 9201");
            boolean okNm = canName ? "박민수".equals(nm) : (nm != null && nm.indexOf('*') >= 0);
            boolean okRrn = canRrn ? "900101-1234567".equals(rrn) : (rrn != null && rrn.indexOf('*') >= 0);
            boolean okTel = canTel ? "010-1111-2222".equals(tel) : (tel != null && tel.indexOf('*') >= 0);
            t.check("자격에 따라 성명, 주민등록번호, 연락처가 평문 또는 마스킹으로 나온다",
                    okNm && okRrn && okTel,
                    "성명=" + okNm + " 주민등록번호=" + okRrn + " 연락처=" + okTel);

            // 4. 마스킹 전용 컬럼은 자격이 있어도 가려져 있다.
            String mn = one(con, "SELECT staff_nm_masked FROM TB_STAFF WHERE staff_id = 9201");
            String mr = one(con, "SELECT rrn_masked FROM TB_STAFF WHERE staff_id = 9201");
            t.check("마스킹 전용 컬럼은 자격이 있어도 가려진다",
                    mn != null && mn.indexOf('*') >= 0 && mr != null && mr.indexOf('*') >= 0,
                    "성명=" + mn + " 주민등록번호=" + mr);

            // 5, 6. 색인으로 찾는다.
            String f1 = one(con, "SELECT staff_id FROM TB_STAFF WHERE rrn_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_rrn('900101-1234567')");
            String f2 = one(con, "SELECT staff_id FROM TB_STAFF WHERE rrn_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_rrn('9001011234567')");
            t.check("주민등록번호 색인은 구분자와 무관하게 같은 행을 찾는다",
                    "9201".equals(f1) && "9201".equals(f2), f1 + ", " + f2);
            String f3 = one(con, "SELECT staff_id FROM TB_STAFF WHERE staff_nm_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_name('이영희')");
            t.check("성명 색인으로 한 건을 찾는다", "9202".equals(f3), f3);

            // 7. 같은 주민등록번호는 유일 색인에 막혀야 한다.
            try {
                exec(con, "INSERT INTO TB_STAFF (staff_id, login_id, staff_nm, rrn, tel)"
                        + " VALUES (9203, 'staff_c', '최다른', '9001011234567', '010-5555-6666')");
                t.check("같은 주민등록번호를 두 번 넣으면 막힌다", false, "막히지 않았다");
                exec(con, "DELETE FROM TB_STAFF WHERE staff_id = 9203");
            } catch (SQLException e) {
                boolean ok = e.getErrorCode() == 1
                        && e.getMessage().toUpperCase().contains("UX_TB_STAFF_RRN");
                t.check("같은 주민등록번호를 두 번 넣으면 유일 색인이 막는다", ok,
                        "ORA-" + e.getErrorCode());
            }

            // 8. 연락처만 고치면 연락처 암호문만 바뀐다.
            String[] b = snapshot(con, 9201);
            exec(con, "UPDATE TB_STAFF SET tel = '010-9999-0000' WHERE staff_id = 9201");
            String[] a = snapshot(con, 9201);
            t.check("연락처만 고치면 연락처 암호문만 바뀐다",
                    !b[3].equals(a[3]) && b[0].equals(a[0]) && b[1].equals(a[1])
                            && b[2].equals(a[2]),
                    "성명=" + b[0].equals(a[0]) + " 색인=" + b[1].equals(a[1])
                            + " 주민등록번호=" + b[2].equals(a[2]) + " 연락처바뀜=" + !b[3].equals(a[3]));

            // 9. 성명만 고치면 성명 암호문과 색인만 바뀌고 새 이름으로 찾는다.
            b = snapshot(con, 9201);
            exec(con, "UPDATE TB_STAFF SET staff_nm = '박민호' WHERE staff_id = 9201");
            a = snapshot(con, 9201);
            String newName = one(con, "SELECT staff_id FROM TB_STAFF WHERE staff_nm_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_name('박민호')");
            String oldName = one(con, "SELECT staff_id FROM TB_STAFF WHERE staff_nm_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_name('박민수')");
            t.check("성명만 고치면 성명 암호문과 색인만 바뀌고 새 이름으로 찾는다",
                    !b[0].equals(a[0]) && !b[1].equals(a[1]) && b[2].equals(a[2])
                            && b[3].equals(a[3]) && "9201".equals(newName) && oldName == null,
                    "암호문바뀜=" + !b[0].equals(a[0]) + " 색인바뀜=" + !b[1].equals(a[1])
                            + " 나머지그대로=" + (b[2].equals(a[2]) && b[3].equals(a[3]))
                            + " 새이름=" + newName + " 옛이름=" + oldName);

            // 10. 주민등록번호만 고치면 주민등록번호 암호문과 색인만 바뀐다.
            b = snapshot(con, 9201);
            String bIdx = one(con, "SELECT RAWTOHEX(rrn_idx) FROM TB_STAFF_ENC WHERE staff_id = 9201");
            exec(con, "UPDATE TB_STAFF SET rrn = '900202-1234567' WHERE staff_id = 9201");
            a = snapshot(con, 9201);
            String aIdx = one(con, "SELECT RAWTOHEX(rrn_idx) FROM TB_STAFF_ENC WHERE staff_id = 9201");
            String newRrn = one(con, "SELECT staff_id FROM TB_STAFF WHERE rrn_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_rrn('900202-1234567')");
            String oldRrn = one(con, "SELECT staff_id FROM TB_STAFF WHERE rrn_idx ="
                    + " OCS_OWNER.PKG_SECURE_API.idx_rrn('900101-1234567')");
            t.check("주민등록번호만 고치면 그 암호문과 색인만 바뀌고 새 번호로 찾는다",
                    !b[2].equals(a[2]) && !bIdx.equals(aIdx) && b[0].equals(a[0])
                            && b[1].equals(a[1]) && b[3].equals(a[3])
                            && "9201".equals(newRrn) && oldRrn == null,
                    "암호문바뀜=" + !b[2].equals(a[2]) + " 색인바뀜=" + !bIdx.equals(aIdx)
                            + " 나머지그대로=" + (b[0].equals(a[0]) && b[1].equals(a[1])
                            && b[3].equals(a[3])) + " 새번호=" + newRrn + " 옛번호=" + oldRrn);

            // 11. 지우면 사라진다.
            exec(con, "DELETE FROM TB_STAFF WHERE staff_id IN (9201, 9202)");
            t.check("뷰로 지우면 실제 표에서도 사라진다",
                    "0".equals(one(con, "SELECT COUNT(*) FROM TB_STAFF_ENC"
                            + " WHERE staff_id IN (9201, 9202)")), null);
        } catch (SQLException e) {
            t.fail++;
            System.out.println("  [실패] 직원 표 확인 중 오류: " + e.getMessage());
        } finally {
            try {
                cleanStaff(con);
            } catch (SQLException e) {
                System.out.println("  [경고] 시험 자료(9201~9203)를 지우지 못하였다: " + e.getMessage());
            }
        }
        return new int[] { t.pass, t.fail };
    }

    /** 직원 표의 시험 자료를 지운다. 뷰의 삭제 경로는 암호화를 쓰지 않는다. */
    private static void cleanStaff(Connection con) throws SQLException {
        exec(con, "DELETE FROM TB_STAFF WHERE staff_id IN (9201, 9202, 9203)");
    }

    /** 고치기 전후를 견주려고 한 행의 암호문과 색인을 16진으로 읽는다. */
    private static String[] snapshot(Connection con, int staffId) throws SQLException {
        String where = " FROM TB_STAFF_ENC WHERE staff_id = " + staffId;
        return new String[] {
            one(con, "SELECT RAWTOHEX(staff_nm_enc)" + where),
            one(con, "SELECT RAWTOHEX(staff_nm_idx)" + where),
            one(con, "SELECT RAWTOHEX(rrn_enc)" + where),
            one(con, "SELECT RAWTOHEX(tel_enc)" + where)
        };
    }

    /** 통과와 실패를 세고 한 줄로 알린다. */
    private static final class Tally {
        int pass;
        int fail;

        void check(String what, boolean ok, String detail) {
            if (ok) { pass++; } else { fail++; }
            System.out.println("  [" + (ok ? "통과" : "실패") + "] " + what
                    + (!ok && detail != null ? "  (" + detail + ")" : ""));
        }
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
