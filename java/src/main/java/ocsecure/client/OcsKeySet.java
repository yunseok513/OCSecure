package ocsecure.client;

/**
 * 한 도메인의 키 묶음.
 *
 * <p>암호화용, 무결성용, 색인용 세 벌을 따로 둔다. 한 키를 여러 용도에 겹쳐 쓰지
 * 않는다는 원칙을 자료 구조 수준에서 지키기 위함이다.
 *
 * <p>이 객체는 애플리케이션이 직접 암복호화를 수행할 때만 필요하다. 데이터베이스
 * 계층에서 암복호화하는 표준 구성에서는 애플리케이션이 키를 알 필요가 없고,
 * 알아서도 안 된다.
 */
public final class OcsKeySet {

    private final int keyId;
    private final int algId;
    private final byte[] encKey;
    private final byte[] macKey;
    private final byte[] idxKey;

    public OcsKeySet(int keyId, int algId, byte[] encKey, byte[] macKey, byte[] idxKey) {
        if (keyId < 0 || keyId > 0xFFFF) {
            throw new OcsCryptoException("키 식별자 범위 초과");
        }
        requireLen(encKey, "암호화 키");
        requireLen(macKey, "무결성 키");
        requireLen(idxKey, "색인 키");
        this.keyId = keyId;
        this.algId = algId;
        this.encKey = encKey.clone();
        this.macKey = macKey.clone();
        this.idxKey = idxKey.clone();
    }

    private static void requireLen(byte[] k, String name) {
        if (k == null || k.length != 32) {
            throw new OcsCryptoException(name + "의 길이는 32바이트여야 한다");
        }
    }

    public int getKeyId() {
        return keyId;
    }

    public int getAlgId() {
        return algId;
    }

    byte[] encKey() {
        return encKey;
    }

    byte[] macKey() {
        return macKey;
    }

    byte[] idxKey() {
        return idxKey;
    }
}
