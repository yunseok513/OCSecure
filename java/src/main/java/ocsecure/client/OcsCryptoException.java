package ocsecure.client;

/**
 * 암호 처리 중 발생한 오류.
 *
 * <p>메시지에 평문이나 키를 담지 않는다. 예외 메시지는 로그로 흘러 들어가기 쉽고,
 * 로그는 암호문 컬럼보다 접근 통제가 느슨하게 관리되는 경우가 많다.
 */
public class OcsCryptoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OcsCryptoException(String message) {
        super(message);
    }

    public OcsCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
