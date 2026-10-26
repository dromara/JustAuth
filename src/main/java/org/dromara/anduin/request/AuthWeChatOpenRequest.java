package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import tools.jackson.databind.JsonNode;

/**
 * 微信开放平台登录
 *
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.1.0
 */
public class AuthWeChatOpenRequest extends AuthDefaultRequest {
    public AuthWeChatOpenRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WECHAT_OPEN);
    }

    public AuthWeChatOpenRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WECHAT_OPEN, authStateCache);
    }

    /**
     * 微信的特殊性，此时返回的信息同时包含 openid 和 access_token
     *
     * @param authCallback 回调返回的参数
     * @return 所有信息
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return this.getToken(accessTokenUrl(authCallback.getCode()));
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String openId = authToken.getOpenId();

        String response = doGetUserInfo(authToken);

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        String location = String.format("%s-%s-%s", getStringValue(userInfoObject, Keys.USERINFO.COUNTRY), getStringValue(userInfoObject, Keys.USERINFO.PROVINCE), getStringValue(userInfoObject, Keys.USERINFO.CITY));

        if (containsKey(userInfoObject, Keys.USERINFO.UNIONID)) {
            authToken.setUnionId(getStringValue(userInfoObject, Keys.USERINFO.UNIONID));
        }

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .username(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .avatar(getStringValue(userInfoObject, "headimgurl"))
                .location(location)
                .uuid(openId)
                .gender(AuthUserGender.getWechatRealGender(getStringValue(userInfoObject, Keys.USERINFO.SEX)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(this.getToken(refreshTokenUrl(oldToken.getRefreshToken())))
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param jsonNode 请求响应内容
     */
    private void checkResponse(JsonNode jsonNode) {
        if (containsKey(jsonNode, Keys.RESPONSE_FIELDS.ERRCODE)) {
            throw new AuthException(getIntValue(jsonNode, Keys.RESPONSE_FIELDS.ERR_NO), getStringValue(jsonNode, Keys.RESPONSE_FIELDS.ERR_DESC));
        }
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl) {
        String response = UnifiedHttpClient.getAdapter().get(accessTokenUrl).getBody();
        JsonNode accessTokenObject = toNode(response);

        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .openId(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPES.OPENID))
                .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.SCOPE, "snsapi_login")
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权码
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2.SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户授权后的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2.SCOPES.OPENID, authToken.getOpenId())
                .queryParam(Keys.USERINFO.LANG, "zh_CN")
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param refreshToken getAccessToken方法返回的refreshToken
     * @return 返回获取userInfo的url
     */
    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
                .build();
    }
}
