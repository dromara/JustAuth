package org.dromara.anduin.exception;

import lombok.Getter;
import org.dromara.anduin.config.AuthSource;
import org.dromara.anduin.enums.AuthResponseStatus;

import java.io.Serial;

/**
 * JustAuth通用异常类
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.8
 */
@Getter
public class AuthException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = -8844734613557245722L;

    /**
     * 业务错误码 {@link AuthResponseStatus#getCode()}
     */
    private int errorCode;

    /**
     * 错误提示信息
     */
    private String errorMsg;

    /**
     * 构造方法，默认错误码：{@link AuthResponseStatus#FAILURE}
     *
     * @param errorMsg 错误信息
     */
    public AuthException(String errorMsg) {
        this(AuthResponseStatus.FAILURE.getCode(), errorMsg);
    }

    /**
     * 构造方法，默认错误码：{@link AuthResponseStatus#FAILURE}，附带认证源信息
     *
     * @param errorMsg 错误信息
     * @param source   认证源
     */
    public AuthException(String errorMsg, AuthSource source) {
        this(AuthResponseStatus.FAILURE.getCode(), errorMsg, source);
    }

    /**
     * 构造方法，指定错误码、错误信息
     *
     * @param errorCode 业务错误码
     * @param errorMsg  错误信息
     */
    public AuthException(int errorCode, String errorMsg) {
        super(errorMsg);
        this.errorCode = errorCode;
        this.errorMsg = errorMsg;
    }

    /**
     * 构造方法，使用响应状态枚举构建异常
     *
     * @param status 认证响应状态枚举
     */
    public AuthException(AuthResponseStatus status) {
        this(status.getCode(), status.getMsg());
    }

    /**
     * 构造方法，指定错误码、错误信息，附带认证源信息（会拼接认证源名称）
     *
     * @param errorCode 业务错误码
     * @param errorMsg  错误信息
     * @param source    认证源
     */
    public AuthException(int errorCode, String errorMsg, AuthSource source) {
        this(errorCode, String.format("%s [%s]", errorMsg, source.getName()));
    }

    /**
     * 构造方法，使用响应状态枚举+认证源构建异常
     *
     * @param status 认证响应状态枚举
     * @param source 认证源
     */
    public AuthException(AuthResponseStatus status, AuthSource source) {
        this(status.getCode(), status.getMsg(), source);
    }

    /**
     * 构造方法，异常信息 + 原始异常堆栈，默认错误码：{@link AuthResponseStatus#FAILURE}
     *
     * @param message 错误信息
     * @param cause   原始异常
     */
    public AuthException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = AuthResponseStatus.FAILURE.getCode();
        this.errorMsg = message;
    }

    /**
     * 构造方法，仅包装原始异常，默认错误码：{@link AuthResponseStatus#FAILURE}
     *
     * @param cause 原始异常
     */
    public AuthException(Throwable cause) {
        super(cause);
        this.errorCode = AuthResponseStatus.FAILURE.getCode();
        this.errorMsg = getMessage();
    }

}
