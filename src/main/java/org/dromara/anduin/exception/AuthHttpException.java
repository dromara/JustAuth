package org.dromara.anduin.exception;

public class AuthHttpException extends RuntimeException {
    /**
     *
     */
    private static final long serialVersionUID = 4866484377036757564L;

    public AuthHttpException(Throwable cause) {
        super(cause);
    }

    public AuthHttpException(String message) {
        super(message);
    }

    public AuthHttpException(String message, Throwable cause) {
        super(message, cause);
    }
}
