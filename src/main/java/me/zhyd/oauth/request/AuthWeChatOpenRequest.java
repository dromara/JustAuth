package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
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

        String location = String.format("%s-%s-%s", getStringValue(userInfoObject, "country"), getStringValue(userInfoObject, "province"), getStringValue(userInfoObject, "city"));

        if (containsKey(userInfoObject, Keys.UNIONID)) {
            authToken.setUnionId(getStringValue(userInfoObject, Keys.UNIONID));
        }

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .username(getStringValue(userInfoObject, Keys.NICKNAME))
                .nickname(getStringValue(userInfoObject, Keys.NICKNAME))
                .avatar(getStringValue(userInfoObject, "headimgurl"))
                .location(location)
                .uuid(openId)
                .gender(AuthUserGender.getWechatRealGender(getStringValue(userInfoObject, "sex")))
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
        if (containsKey(jsonNode, Keys.VARIANT__ERRCODE)) {
            throw new AuthException(getIntValue(jsonNode, "error_no"), getStringValue(jsonNode, "error_desc"));
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
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .openId(getStringValue(accessTokenObject, Keys.OAUTH2_SCOPE__OPENID))
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
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__SCOPE, "snsapi_login")
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
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
                .queryParam(Keys.OAUTH2__CODE, code)
                .queryParam(Keys.APPID, config.getClientId())
                .queryParam("secret", config.getClientSecret())
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
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
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2_SCOPE__OPENID, authToken.getOpenId())
                .queryParam("lang", "zh_CN")
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
                .queryParam(Keys.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2__REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2__REFRESH_TOKEN)
                .build();
    }
}
