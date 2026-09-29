package ocsecure.client;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 기존 비밀번호 체계 (이행 기간 한정).
 *
 * <p>조사로 확인된 기존 저장 방식은 Base64(SHA-256(비밀번호))이며 솔트도 아이디
 * 결합도 없다. 근거는 셋이다. 저장값이 Base64 44자에 '=' 종료이므로 32바이트이고,
 * 32바이트를 내는 해시는 사실상 SHA-256 뿐이다. 그리고 서로 다른 사용자 사이에
 * 중복이 존재하므로 솔트와 아이디 결합이 함께 배제된다.
 *
 * <p>이는 추정이다. 배포 전에 실제 계정으로 {@link #selfCheck} 를 통과시켜야 한다.
 *
 * <p>이 클래스는 이행이 끝나면 삭제한다. 남겨 두면 약한 검증 경로가 계속 남는다.
 *
 * <p><b>이 방식은 약하다.</b> 솔트가 없어 같은 비밀번호가 같은 값이 되고, 계산이
 * 한 번뿐이라 유출되면 흔한 비밀번호는 즉시 복원된다. 그래서 이행 기간에도 옛
 * 방식으로 로그인한 사용자에게는 비밀번호 변경을 강제한다.
 */
public final class OcsLegacyPassword {

    public static final int LEGACY_LEN = 44;

    /** 예전 시스템은 문자집합이 갈리는 경우가 있다. 확정 전까지 셋 다 시도한다. */
    private static final String[] CHARSETS = {"UTF-8", "MS949", "EUC-KR"};

    private OcsLegacyPassword() {
    }

    public static String legacyHash(String password, Charset charset) {
        if (password == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(md.digest(password.getBytes(charset)));
        } catch (Exception e) {
            throw new OcsCryptoException("기존 방식 계산 실패", e);
        }
    }

    public static String legacyHash(String password) {
        return legacyHash(password, StandardCharsets.UTF_8);
    }

    /** 기존 방식의 저장값으로 보이는가. */
    public static boolean isLegacy(String stored) {
        if (stored == null || stored.length() != LEGACY_LEN || stored.charAt(43) != '=') {
            return false;
        }
        for (int i = 0; i < 43; i++) {
            char c = stored.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                      || (c >= '0' && c <= '9') || c == '+' || c == '/';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    public static boolean verifyLegacy(String password, String stored, Charset charset) {
        if (password == null || !isLegacy(stored)) {
            return false;
        }
        return MessageDigest.isEqual(
                legacyHash(password, charset).getBytes(StandardCharsets.US_ASCII),
                stored.getBytes(StandardCharsets.US_ASCII));
    }

    public static boolean verifyLegacy(String password, String stored) {
        return verifyLegacy(password, stored, StandardCharsets.UTF_8);
    }

    /**
     * 실제 계정의 평문과 저장값으로 가정이 맞는지 확인한다.
     *
     * @return 맞으면 그 문자집합의 이름, 틀리면 null. null 이면 조사부터 다시 해야 한다.
     */
    public static String selfCheck(String password, String stored) {
        if (password == null || stored == null) {
            return null;
        }
        for (String cs : CHARSETS) {
            try {
                if (legacyHash(password, Charset.forName(cs)).equals(stored)) {
                    return cs;
                }
            } catch (Exception e) {
                // 지원하지 않는 문자집합은 건너뛴다
            }
        }
        return null;
    }
}
