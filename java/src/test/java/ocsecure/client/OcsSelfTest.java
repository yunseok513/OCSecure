package ocsecure.client;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

/**
 * 자바 연동 모듈 자체 시험.
 *
 * <p>핵심은 고정 시험 벡터 대조다. 파이썬 참조 구현이 만들어 낸 값과 이 자바
 * 구현의 결과가 바이트 단위로 같은지 확인한다. 같은 벡터를 PL/SQL 쪽 자체 시험도
 * 통과하므로, 세 구현이 서로 호환된다고 볼 수 있다.
 *
 * <p>외부 시험 도구를 쓰지 않는다. 연동 모듈이 의존성 없이 돌아가야 한다는 원칙을
 * 시험 코드에도 적용하였다.
 *
 * <pre>
 *   javac -d out $(find java/src -name '*.java')
 *   java -cp out ocsecure.client.OcsSelfTest tests/vectors/kat.properties
 * </pre>
 */
public final class OcsSelfTest {

    private static int pass;
    private static int fail;

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : "tests/vectors/kat.properties";
        Properties v = load(path);

        System.out.println("=== OCSecure 자바 연동 모듈 자체 시험 ===");

        byte[] kek = hex(v, "kek");
        byte[] encKey = hex(v, "enc_key");
        byte[] macKey = hex(v, "mac_key");
        byte[] idxKey = hex(v, "idx_key");
        byte[] iv = hex(v, "iv");
        int keyId = Integer.parseInt(v.getProperty("key_id"));

        OcsKeySet key = new OcsKeySet(keyId, OcsCrypto.ALG_AES256_CBC_HMAC_SHA256,
                encKey, macKey, idxKey);

        // 1. 고정 벡터 대조
        for (String name : v.getProperty("sample.names").split(",")) {
            String plain = v.getProperty("sample." + name + ".plain");
            String norm = v.getProperty("sample." + name + ".norm");
            String cipher = v.getProperty("sample." + name + ".cipher");
            String bidx = v.getProperty("sample." + name + ".bidx");

            if (plain == null) {
                plain = "";   // Properties 는 빈 값을 빈 문자열로 돌려준다
            }

            chk("암호화 결과가 참조 구현과 일치 (" + name + ")",
                    cipher.equals(OcsCrypto.toHex(OcsCrypto.encryptWithIv(plain, key, iv))));

            chk("복호화 결과가 원문과 일치 (" + name + ")",
                    plain.equals(OcsCrypto.decrypt(OcsCrypto.fromHex(cipher), key)));

            chk("색인 값이 참조 구현과 일치 (" + name + ")",
                    bidx.equals(OcsCrypto.toHex(OcsCrypto.blindIndex(plain, key, norm))));
        }

        // 2. 확률적 암호화
        byte[] a = OcsCrypto.encrypt("880101-1234567", key);
        byte[] b = OcsCrypto.encrypt("880101-1234567", key);
        chk("같은 평문을 두 번 암호화하면 서로 다른 암호문", !Arrays.equals(a, b));
        chk("그럼에도 둘 다 같은 원문으로 복호화",
                OcsCrypto.decrypt(a, key).equals(OcsCrypto.decrypt(b, key)));

        // 3. 길이 산정
        chk("주민등록번호 암호문 길이가 68바이트",
                OcsCrypto.encryptWithIv("880101-1234567", key, iv).length == 68);

        // 4. 헤더 판독
        chk("헤더에서 키 식별자를 읽을 수 있다", OcsCrypto.keyIdOf(a) == keyId);

        // 5. 변조 탐지
        for (int pos : new int[] {0, 1, 3, 5, 25, a.length - 1}) {
            byte[] bad = a.clone();
            bad[pos] ^= 0x01;
            boolean caught = false;
            try {
                OcsCrypto.decrypt(bad, key);
            } catch (OcsCryptoException e) {
                caught = true;
            }
            chk("암호문 " + pos + "번째 바이트 변조가 탐지된다", caught);
        }

        // 6. 정규화
        chk("구분자가 있든 없든 같은 색인 값",
                Arrays.equals(OcsCrypto.blindIndex("880101-1234567", key, OcsCrypto.NORM_DIGITS),
                        OcsCrypto.blindIndex("8801011234567", key, OcsCrypto.NORM_DIGITS)));
        chk("TRIM 은 공백만 제거한다 (탭은 남는다)",
                "\tx".equals(OcsCrypto.normalize(" \tx ", OcsCrypto.NORM_TRIM)));

        // 7. 키 래핑
        chk("참조 구현이 감싼 키를 그대로 풀 수 있다",
                Arrays.equals(encKey, OcsCrypto.unwrapKey(hex(v, "wrapped_enc_key"), kek)));
        chk("감싼 키가 참조 구현과 일치",
                v.getProperty("wrapped_idx_key")
                        .equals(OcsCrypto.toHex(OcsCrypto.wrapKey(idxKey, kek, iv))));

        // 8. 비밀번호
        byte[] salt = hex(v, "pwd_salt");
        int iter = Integer.parseInt(v.getProperty("pwd_iterations"));
        int pwdCount = Integer.parseInt(v.getProperty("pwd.count"));
        for (int i = 0; i < pwdCount; i++) {
            String plain = v.getProperty("pwd." + i + ".plain", "");
            String stored = v.getProperty("pwd." + i + ".stored");
            chk("비밀번호 저장값이 참조 구현과 일치 (" + i + ")",
                    stored.equals(OcsCrypto.toHex(OcsCrypto.passwordHash(plain, salt, iter))));
            chk("올바른 비밀번호가 검증을 통과 (" + i + ")",
                    OcsCrypto.passwordVerify(plain, OcsCrypto.fromHex(stored)));
            chk("틀린 비밀번호는 통과하지 못함 (" + i + ")",
                    !OcsCrypto.passwordVerify(plain + "x", OcsCrypto.fromHex(stored)));
        }
        boolean emptyRejected = false;
        try {
            OcsCrypto.passwordHash("", salt, iter);
        } catch (OcsCryptoException e) {
            emptyRejected = true;
        }
        chk("빈 비밀번호는 거부된다", emptyRejected);

        chk("반복 횟수 상향 판정",
                OcsCrypto.passwordNeedsUpgrade(OcsCrypto.passwordHash("x", salt, 1000), 10000));

        // 9. 접속 증표
        OcsAppProof proof = new OcsAppProof(idxKey);
        byte[] p1 = proof.build("hong", 1700000000L, 123L);
        chk("같은 입력이면 같은 증표", Arrays.equals(p1, proof.build("hong", 1700000000L, 123L)));
        chk("세션이 다르면 증표가 다르다",
                !Arrays.equals(p1, proof.build("hong", 1700000000L, 124L)));
        chk("증표가 데이터베이스 쪽 계산 규칙과 같다",
                Arrays.equals(p1, OcsCrypto.hmac(
                        "hong|1700000000|123".getBytes(StandardCharsets.UTF_8), idxKey)));

        // 10. 널 처리
        chk("널을 암호화하면 널", OcsCrypto.encrypt(null, key) == null);
        chk("널을 복호화하면 널", OcsCrypto.decrypt(null, key) == null);
        chk("널의 색인 값은 널", OcsCrypto.blindIndex(null, key, OcsCrypto.NORM_NONE) == null);

        System.out.println("=== 통과 " + pass + " / 실패 " + fail + " ===");
        if (fail > 0) {
            System.exit(1);
        }
    }

    private static Properties load(String path) throws Exception {
        Properties p = new Properties();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
            p.load(r);
        }
        return p;
    }

    private static byte[] hex(Properties p, String key) {
        return OcsCrypto.fromHex(p.getProperty(key));
    }

    private static void chk(String name, boolean ok) {
        if (ok) {
            pass++;
            System.out.println("  [통과] " + name);
        } else {
            fail++;
            System.out.println("  [실패] " + name);
        }
    }
}
