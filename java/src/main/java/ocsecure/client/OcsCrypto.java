package ocsecure.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * OCSecure 암호문 포맷의 자바 구현.
 *
 * <p>PL/SQL 구현(sql/02_packages) 및 파이썬 참조 구현(tools/refimpl)과 바이트 단위로
 * 같은 결과를 낸다. 세 구현이 같은 고정 시험 벡터를 통과하는지 확인하는 시험이
 * 각 언어마다 있으며, 자바 쪽은 OcsSelfTest 가 그 역할을 한다.
 *
 * <p>외부 의존성이 없다. JDK 표준 라이브러리만 쓰므로 전자정부 표준프레임워크
 * 프로젝트에 그대로 넣을 수 있다.
 *
 * <p>암호문 구조는 다음과 같다.
 *
 * <pre>
 *   ver(1) | alg(1) | keyId(2) | iv(16) | ciphertext(n) | tag(32)
 * </pre>
 *
 * <p>태그는 ver 부터 ciphertext 까지 전체에 대한 HMAC-SHA256 이다. 복호화할 때는
 * 태그를 먼저 검증하고 실패하면 복호화를 수행하지 않는다. 이 순서를 바꾸면
 * 암호문 조작 공격의 여지가 생긴다.
 *
 * <p><b>주의.</b> 이 클래스를 애플리케이션에서 직접 쓰는 것은 표준 구성이 아니다.
 * 표준 구성에서는 데이터베이스의 PKG_SECURE_API 가 암복호화를 수행하고 애플리케이션은
 * 키를 갖지 않는다. 이 클래스가 필요한 경우는 세 가지뿐이다. 첫째는 접속 증표를
 * 만들 때, 둘째는 데이터베이스를 거치지 않는 외부 연계 자료를 다룰 때, 셋째는
 * 연동 시험에서 결과를 대조할 때다.
 */
public final class OcsCrypto {

    /** 암호문 포맷 버전. */
    public static final int FMT_VERSION = 0x01;

    /** AES-256/CBC + HMAC-SHA256. 임시 구현체(오라클 내장 기능)용 식별자. */
    public static final int ALG_AES256_CBC_HMAC_SHA256 = 0x01;

    public static final int IV_LEN = 16;
    public static final int TAG_LEN = 32;
    public static final int HDR_LEN = 4;
    /** 가장 짧은 암호문의 길이. 헤더 4 + 초기화 벡터 16 + 한 블록 16 + 태그 32. */
    public static final int MIN_LEN = HDR_LEN + IV_LEN + 16 + TAG_LEN;

    public static final int KDF_VERSION = 0x01;
    public static final int KDF_PBKDF2_HMAC_SHA256 = 0x01;
    public static final int PWD_SALT_LEN = 16;
    public static final int PWD_DK_LEN = 32;
    public static final int PWD_BLOB_LEN = 2 + 4 + PWD_SALT_LEN + PWD_DK_LEN;

    /** 정규화 방식. 데이터베이스의 SEC_DOMAIN.norm_mode 와 의미가 같아야 한다. */
    public static final String NORM_NONE = "NONE";
    public static final String NORM_TRIM = "TRIM";
    public static final String NORM_UPPER_TRIM = "UPPER_TRIM";
    public static final String NORM_DIGITS = "DIGITS";

    private static final String KEK_ENC_LABEL = "OCSECURE/KEK/ENC/v1";
    private static final String KEK_MAC_LABEL = "OCSECURE/KEK/MAC/v1";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private OcsCrypto() {
    }

    // ------------------------------------------------------------ 정규화

    /**
     * 색인 값을 계산하기 전에 평문을 다듬는다.
     *
     * <p>오라클 쪽 구현과 의미가 정확히 같아야 한다. 그래서 자바의 {@code trim()} 을
     * 쓰지 않는다. {@code trim()} 은 탭과 줄바꿈까지 제거하지만 오라클의 TRIM 은
     * 공백만 제거하므로, 그대로 쓰면 두 구현의 결과가 어긋난다.
     */
    public static String normalize(String plain, String mode) {
        if (plain == null) {
            return null;
        }
        if (NORM_NONE.equals(mode)) {
            return plain;
        }
        if (NORM_TRIM.equals(mode)) {
            return stripSpaces(plain);
        }
        if (NORM_UPPER_TRIM.equals(mode)) {
            return stripSpaces(plain).toUpperCase();
        }
        if (NORM_DIGITS.equals(mode)) {
            StringBuilder sb = new StringBuilder(plain.length());
            for (int i = 0; i < plain.length(); i++) {
                char c = plain.charAt(i);
                if (c >= '0' && c <= '9') {
                    sb.append(c);
                }
            }
            return sb.toString();
        }
        throw new OcsCryptoException("알 수 없는 정규화 방식: " + mode);
    }

    private static String stripSpaces(String s) {
        int b = 0;
        int e = s.length();
        while (b < e && s.charAt(b) == ' ') {
            b++;
        }
        while (e > b && s.charAt(e - 1) == ' ') {
            e--;
        }
        return s.substring(b, e);
    }

    // ------------------------------------------------------- 양방향 암복호화

    /** 문자열을 암호화한다. 초기화 벡터는 매번 새로 뽑는다. */
    public static byte[] encrypt(String plain, OcsKeySet key) {
        return plain == null ? null
                : encryptBytes(plain.getBytes(StandardCharsets.UTF_8), key, null);
    }

    /**
     * 고정 초기화 벡터로 암호화한다. 시험 벡터 대조 전용이다.
     *
     * <p>업무 코드에서 호출하면 같은 평문이 같은 암호문이 되어 빈도 분석에 노출된다.
     */
    public static byte[] encryptWithIv(String plain, OcsKeySet key, byte[] iv) {
        return plain == null ? null
                : encryptBytes(plain.getBytes(StandardCharsets.UTF_8), key, iv);
    }

    public static byte[] encryptBytes(byte[] plain, OcsKeySet key, byte[] iv) {
        if (plain == null) {
            return null;
        }
        byte[] useIv = iv;
        if (useIv == null) {
            useIv = new byte[IV_LEN];
            RANDOM.nextBytes(useIv);
        }
        if (useIv.length != IV_LEN) {
            throw new OcsCryptoException("초기화 벡터 길이 오류");
        }
        if (key.getAlgId() != ALG_AES256_CBC_HMAC_SHA256) {
            throw new OcsCryptoException("이 구현이 지원하지 않는 알고리즘 식별자: "
                    + key.getAlgId());
        }

        byte[] ct = cipher(Cipher.ENCRYPT_MODE, plain, key.encKey(), useIv);

        byte[] signed = new byte[HDR_LEN + IV_LEN + ct.length];
        signed[0] = (byte) FMT_VERSION;
        signed[1] = (byte) key.getAlgId();
        signed[2] = (byte) ((key.getKeyId() >> 8) & 0xFF);
        signed[3] = (byte) (key.getKeyId() & 0xFF);
        System.arraycopy(useIv, 0, signed, HDR_LEN, IV_LEN);
        System.arraycopy(ct, 0, signed, HDR_LEN + IV_LEN, ct.length);

        byte[] tag = hmac(signed, key.macKey());
        byte[] out = new byte[signed.length + TAG_LEN];
        System.arraycopy(signed, 0, out, 0, signed.length);
        System.arraycopy(tag, 0, out, signed.length, TAG_LEN);
        return out;
    }

    public static String decrypt(byte[] blob, OcsKeySet key) {
        byte[] out = decryptBytes(blob, key);
        return out == null ? null : new String(out, StandardCharsets.UTF_8);
    }

    public static byte[] decryptBytes(byte[] blob, OcsKeySet key) {
        if (blob == null) {
            return null;
        }
        checkBlob(blob);

        byte[] signed = Arrays.copyOfRange(blob, 0, blob.length - TAG_LEN);
        byte[] tag = Arrays.copyOfRange(blob, blob.length - TAG_LEN, blob.length);

        // 무결성 검증이 먼저다. 실패하면 복호화를 시도조차 하지 않는다.
        if (!MessageDigest.isEqual(hmac(signed, key.macKey()), tag)) {
            throw new OcsCryptoException("무결성 검증 실패");
        }

        byte[] iv = Arrays.copyOfRange(signed, HDR_LEN, HDR_LEN + IV_LEN);
        byte[] ct = Arrays.copyOfRange(signed, HDR_LEN + IV_LEN, signed.length);
        return cipher(Cipher.DECRYPT_MODE, ct, key.encKey(), iv);
    }

    /** 무결성 검증 전에 헤더만 읽는다. 어느 키로 만든 암호문인지 찾을 때 쓴다. */
    public static int keyIdOf(byte[] blob) {
        checkBlob(blob);
        return ((blob[2] & 0xFF) << 8) | (blob[3] & 0xFF);
    }

    public static int algIdOf(byte[] blob) {
        checkBlob(blob);
        return blob[1] & 0xFF;
    }

    private static void checkBlob(byte[] blob) {
        if (blob == null || blob.length < MIN_LEN) {
            throw new OcsCryptoException("암호문 길이 부족: "
                    + (blob == null ? "null" : String.valueOf(blob.length)));
        }
        if ((blob[0] & 0xFF) != FMT_VERSION) {
            throw new OcsCryptoException("알 수 없는 포맷 버전: " + (blob[0] & 0xFF));
        }
    }

    // ------------------------------------------------------- 블라인드 인덱스

    /**
     * 검색용 색인 값을 만든다.
     *
     * <p>단순 해시를 쓰지 않는 이유가 있다. 주민등록번호처럼 값의 범위가 좁은
     * 데이터는 전수 대입으로 원문이 복원되므로, 키가 결합된 방식이어야 한다.
     */
    public static byte[] blindIndex(String plain, OcsKeySet key, String normMode) {
        if (plain == null) {
            return null;
        }
        String norm = normalize(plain, normMode);
        return hmac(norm.getBytes(StandardCharsets.UTF_8), key.idxKey());
    }

    // ------------------------------------------------------------ 일방향

    /**
     * 반복 기반 키 유도. 출력 길이가 해시 출력과 같으므로 블록은 하나뿐이다.
     *
     * <p>JDK 의 PBKDF2 구현을 쓰지 않고 직접 구현한 이유는, 오라클 쪽 구현과 구조를
     * 눈으로 대조할 수 있게 하기 위함이다. 정확성은 시험 벡터로 확인한다.
     */
    public static byte[] pbkdf2Sha256(byte[] password, byte[] salt, int iterations) {
        byte[] first = new byte[salt.length + 4];
        System.arraycopy(salt, 0, first, 0, salt.length);
        first[salt.length + 3] = 1;

        byte[] u = hmac(first, password);
        byte[] t = u.clone();
        for (int i = 1; i < iterations; i++) {
            u = hmac(u, password);
            for (int j = 0; j < t.length; j++) {
                t[j] ^= u[j];
            }
        }
        return t;
    }

    public static byte[] passwordHash(String password, int iterations) {
        byte[] salt = new byte[PWD_SALT_LEN];
        RANDOM.nextBytes(salt);
        return passwordHash(password, salt, iterations);
    }

    /**
     * 비밀번호 저장값을 만든다.
     *
     * <pre>
     *   ver(1) | kdf(1) | iterations(4) | salt(16) | dk(32)
     * </pre>
     *
     * <p>반복 횟수를 저장값 안에 담으므로, 나중에 횟수를 올려도 기존 사용자와
     * 신규 사용자가 공존한다.
     */
    public static byte[] passwordHash(String password, byte[] salt, int iterations) {
        // 빈 비밀번호는 거부한다. 저장되어서는 안 되는 값이며, 구현마다 동작이
        // 갈리는 지점이기도 하다. 파이썬 참조 구현과 오라클 구현도 함께 거부한다.
        if (password == null || password.isEmpty()) {
            throw new OcsCryptoException("빈 비밀번호는 저장할 수 없다");
        }
        if (salt == null || salt.length != PWD_SALT_LEN) {
            throw new OcsCryptoException("솔트 길이 오류");
        }
        if (iterations < 1) {
            throw new OcsCryptoException("반복 횟수가 1보다 작음");
        }
        byte[] dk = pbkdf2Sha256(password.getBytes(StandardCharsets.UTF_8), salt, iterations);

        byte[] out = new byte[PWD_BLOB_LEN];
        out[0] = (byte) KDF_VERSION;
        out[1] = (byte) KDF_PBKDF2_HMAC_SHA256;
        out[2] = (byte) ((iterations >> 24) & 0xFF);
        out[3] = (byte) ((iterations >> 16) & 0xFF);
        out[4] = (byte) ((iterations >> 8) & 0xFF);
        out[5] = (byte) (iterations & 0xFF);
        System.arraycopy(salt, 0, out, 6, PWD_SALT_LEN);
        System.arraycopy(dk, 0, out, 6 + PWD_SALT_LEN, PWD_DK_LEN);
        return out;
    }

    public static boolean passwordVerify(String password, byte[] stored) {
        if (password == null || password.isEmpty()
                || stored == null || stored.length != PWD_BLOB_LEN) {
            return false;
        }
        if ((stored[0] & 0xFF) != KDF_VERSION
                || (stored[1] & 0xFF) != KDF_PBKDF2_HMAC_SHA256) {
            return false;
        }
        int iterations = ((stored[2] & 0xFF) << 24) | ((stored[3] & 0xFF) << 16)
                | ((stored[4] & 0xFF) << 8) | (stored[5] & 0xFF);
        byte[] salt = Arrays.copyOfRange(stored, 6, 6 + PWD_SALT_LEN);
        byte[] dk = Arrays.copyOfRange(stored, 6 + PWD_SALT_LEN, PWD_BLOB_LEN);

        byte[] calc = pbkdf2Sha256(password.getBytes(StandardCharsets.UTF_8), salt, iterations);
        return MessageDigest.isEqual(calc, dk);
    }

    /** 저장값의 반복 횟수가 현재 기준보다 낮으면 참. 로그인 성공 시점에 다시 계산한다. */
    public static boolean passwordNeedsUpgrade(byte[] stored, int currentIterations) {
        if (stored == null || stored.length != PWD_BLOB_LEN) {
            return true;
        }
        int iterations = ((stored[2] & 0xFF) << 24) | ((stored[3] & 0xFF) << 16)
                | ((stored[4] & 0xFF) << 8) | (stored[5] & 0xFF);
        return iterations < currentIterations;
    }

    // ------------------------------------------------------------ 키 래핑

    /** 마스터 키에서 래핑용 두 키를 유도한다. 라벨을 달리하여 용도를 분리한다. */
    public static byte[][] kekSubkeys(byte[] kek) {
        if (kek == null || kek.length < 32) {
            throw new OcsCryptoException("마스터 키는 32바이트 이상이어야 한다");
        }
        return new byte[][] {
            hmac(KEK_ENC_LABEL.getBytes(StandardCharsets.UTF_8), kek),
            hmac(KEK_MAC_LABEL.getBytes(StandardCharsets.UTF_8), kek)
        };
    }

    public static byte[] wrapKey(byte[] rawKey, byte[] kek, byte[] iv) {
        byte[][] sub = kekSubkeys(kek);
        OcsKeySet wrapper = new OcsKeySet(0, ALG_AES256_CBC_HMAC_SHA256,
                sub[0], sub[1], sub[1]);
        return encryptBytes(rawKey, wrapper, iv);
    }

    public static byte[] unwrapKey(byte[] wrapped, byte[] kek) {
        byte[][] sub = kekSubkeys(kek);
        OcsKeySet wrapper = new OcsKeySet(0, ALG_AES256_CBC_HMAC_SHA256,
                sub[0], sub[1], sub[1]);
        return decryptBytes(wrapped, wrapper);
    }

    // ------------------------------------------------------------ 보조

    public static byte[] hmac(byte[] message, byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new OcsCryptoException("메시지 인증 코드 계산 실패", e);
        }
    }

    private static byte[] cipher(int mode, byte[] input, byte[] key, byte[] iv) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(input);
        } catch (Exception e) {
            // 실패 사유를 호출자에게 자세히 알리지 않는다. 공격자에게 단서가 된다.
            throw new OcsCryptoException("암호 연산 실패", e);
        }
    }

    /** 오라클의 RAWTOHEX 와 같은 형태(대문자)로 만든다. */
    public static String toHex(byte[] b) {
        if (b == null) {
            return null;
        }
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            out[i * 2] = HEX[(b[i] >> 4) & 0x0F];
            out[i * 2 + 1] = HEX[b[i] & 0x0F];
        }
        return new String(out);
    }

    public static byte[] fromHex(String hex) {
        if (hex == null) {
            return null;
        }
        if ((hex.length() & 1) != 0) {
            throw new OcsCryptoException("16진 문자열의 길이가 홀수다");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
