package org.dromara.anduin.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.JsonUtils;

/**
 * QQ小程序登陆 Request 请求
 * <p>
 * 参照微信小程序实现
 *
 * @author hurentian
 * @since 2024-10-08
 */
public class AuthQQMiniProgramRequest extends AuthDefaultRequest {
    public AuthQQMiniProgramRequest(AuthConfig config) {
        super(config, AuthDefaultSource.QQ_MINI_PROGRAM);
    }

    public AuthQQMiniProgramRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.QQ_MINI_PROGRAM, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        // 参见 https://q.qq.com/wiki/develop/miniprogram/server/open_port/port_login.html#code2session 文档
        // 使用 code 获取对应的 openId、unionId 等字段
        String response = doGetAuthorizationCode(authCallback.getCode());

        JSCode2SessionResponse accessTokenObject = JsonUtils.toObject(response, JSCode2SessionResponse.class);
        assert accessTokenObject != null;
        checkResponse(accessTokenObject);
        // 拼装结果
        return AuthToken.builder()
                .accessToken(accessTokenObject.getSessionKey())
                .openId(accessTokenObject.getOpenid())
                .unionId(accessTokenObject.getUnionId())
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        // 参见 https://q.qq.com/wiki/develop/game/API/open-port/user-info.html#qq-getuserinfo 文档
        // 如果需要用户信息，需要在小程序调用函数后传给后端
        return AuthUser.builder()
                .username("")
                .nickname("")
                .avatar("")
                .uuid(authToken.getOpenId())
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param response 请求响应内容
     */
    private void checkResponse(JSCode2SessionResponse response) {
        if (response.getErrorCode() != 0) {
            throw new AuthException(response.getErrorCode(), response.getErrorMsg());
        }
    }

    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2.SECRET, config.getClientSecret())
                .queryParam("js_code", code)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .build();
    }

    @Data
    private static class JSCode2SessionResponse {

        @JsonProperty(Keys.RESPONSE_FIELDS.ERRCODE)
        private int errorCode;
        @JsonProperty(Keys.RESPONSE_FIELDS.ERRMSG)
        private String errorMsg;
        @JsonProperty("session_key")
        private String sessionKey;
        private String openid;
        @JsonProperty(Keys.USERINFO.UNIONID)
        private String unionId;

    }

}
