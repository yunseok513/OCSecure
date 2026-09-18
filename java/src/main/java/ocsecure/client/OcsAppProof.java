package ocsecure.client;

import java.nio.charset.StandardCharsets;

/**
 * 접속 증표 생성기.
 *
 * <p>데이터베이스의 정책 계층은 정당한 애플리케이션 경로를 거친 세션에서만
 * 복호화를 허용한다. 그 경로를 증명하는 것이 이 증표다. 계산에 쓰는 비밀 키는
 * 애플리케이션 서버의 설정에만 있고 데이터베이스에는 감싸인 채로만 있으므로,
 * 데이터베이스 접속 정보만 손에 넣은 사람은 증표를 만들 수 없다.
 *
 * <p>증표에는 세션 식별자와 시각이 함께 묶인다. 세션 식별자가 묶여 있어 다른
 * 세션에서 가로챈 증표를 그대로 쓸 수 없고, 시각이 묶여 있어 오래된 증표가
 * 거부된다.
 *
 * <p>비밀 키는 소스나 설정 파일에 평문으로 두지 않는다. 운영 환경에서는 키 관리
 * 제품이나 기동 시점에 주입되는 환경 값에서 읽어야 한다.
 */
public final class OcsAppProof {

    private final byte[] appCtxKey;

    public OcsAppProof(byte[] appCtxKey) {
        if (appCtxKey == null || appCtxKey.length != 32) {
            throw new OcsCryptoException("증표 키의 길이는 32바이트여야 한다");
        }
        this.appCtxKey = appCtxKey.clone();
    }

    /** 협정 세계시 기준 초. 데이터베이스 쪽 검증도 같은 기준을 쓴다. */
    public static long nowEpochSeconds() {
        return System.currentTimeMillis() / 1000L;
    }

    /**
     * 증표를 만든다.
     *
     * @param appUser 업무 사용자 식별자. 데이터베이스 계정이 아니라 실제 사용자다.
     * @param epoch   협정 세계시 기준 초
     * @param sid     현재 데이터베이스 세션의 식별자
     */
    public byte[] build(String appUser, long epoch, long sid) {
        if (appUser == null || appUser.isEmpty()) {
            throw new OcsCryptoException("응용 사용자 식별자가 비어 있음");
        }
        String message = appUser + "|" + epoch + "|" + sid;
        return OcsCrypto.hmac(message.getBytes(StandardCharsets.UTF_8), appCtxKey);
    }

    /** 오라클 바인딩에 그대로 넣을 수 있는 16진 문자열 형태. */
    public String buildHex(String appUser, long epoch, long sid) {
        return OcsCrypto.toHex(build(appUser, epoch, sid));
    }
}
