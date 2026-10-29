package org.dromara.anduin.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * JustAuth通用的状态码对照表
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.8
 */
@Getter
@AllArgsConstructor
public enum AuthResponseStatus {

    /**
     * 2000：正常；
     * other：调用异常，具体异常内容见{@code msg}
     */
    SUCCESS(2000, "Success"),

    /**
     * 5000：通用失败
     */
    FAILURE(5000, "Failure"),

    /**
     * 5001：功能未实现
     */
    NOT_IMPLEMENTED(5001, "Not Implemented"),

    /**
     * 5002：参数缺失
     */
    PARAMETER_INCOMPLETE(5002, "Parameter incomplete"),

    /**
     * 5003：不支持该操作
     */
    UNSUPPORTED(5003, "Unsupported operation"),

    /**
     * 5004：认证源不能为空
     */
    NO_AUTH_SOURCE(5004, "AuthDefaultSource cannot be null"),

    /**
     * 5005：无法识别的平台
     */
    UNIDENTIFIED_PLATFORM(5005, "Unidentified platform"),

    /**
     * 5006：非法回调地址 redirect uri
     */
    ILLEGAL_REDIRECT_URI(5006, "Illegal redirect uri"),

    /**
     * 5007：非法请求
     */
    ILLEGAL_REQUEST(5007, "Illegal request"),

    /**
     * 5008：非法授权码 code
     */
    ILLEGAL_CODE(5008, "Illegal code"),

    /**
     * 5009：非法 state（防跨站参数校验失败）
     */
    ILLEGAL_STATUS(5009, "Illegal state"),

    /**
     * 5010：refresh_token 不能为空，必须传入
     */
    REQUIRED_REFRESH_TOKEN(5010, "The refresh token is required; it must not be null"),

    /**
     * 5011：token 无效/非法
     */
    ILLEGAL_TOKEN(5011, "Invalid token"),

    /**
     * 5012：kid 密钥标识非法
     */
    ILLEGAL_KID(5012, "Invalid key identifier(kid)"),

    /**
     * 5013：team id 非法
     */
    ILLEGAL_TEAM_ID(5013, "Invalid team id"),

    /**
     * 5014：client_id 非法
     */
    ILLEGAL_CLIENT_ID(5014, "Invalid client id"),

    /**
     * 5015：client_secret 非法
     */
    ILLEGAL_CLIENT_SECRET(5015, "Invalid client secret"),

    /**
     * 5016：企业微信 agent id 非法
     */
    ILLEGAL_WECHAT_AGENT_ID(5016, "Illegal wechat agent id");

    private final int code;
    private final String msg;
}

