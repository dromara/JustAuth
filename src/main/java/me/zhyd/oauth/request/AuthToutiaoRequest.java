package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthToutiaoErrorCode;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import tools.jackson.databind.JsonNode;

/**
 * 今日头条登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.6.0-beta
 */
public class AuthToutiaoRequest extends AuthDefaultRequest {

    public AuthToutiaoRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TOUTIAO);
    }

    public AuthToutiaoRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TOUTIAO, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doGetAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .openId(getStringValue(accessTokenObject, Keys.VARIANT__OPEN_ID))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userResponse = doGetUserInfo(authToken);

        JsonNode userProfile = toNode(userResponse);

        this.checkResponse(userProfile);

        JsonNode userInfoObject = getDataNode(userProfile);

        boolean isAnonymousUser = getIntValue(userInfoObject, "uid_type") == 14;
        String anonymousUserName = "匿名用户";

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.UID))
                .username(isAnonymousUser ? anonymousUserName : getStringValue(userInfoObject, "screen_name"))
                .nickname(isAnonymousUser ? anonymousUserName : getStringValue(userInfoObject, "screen_name"))
                .avatar(getStringValue(userInfoObject, Keys.AVATAR_URL))
                .remark(getStringValue(userInfoObject, Keys.DESCRIPTION))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.GENDER)))
                .token(authToken)
                .source(source.toString())
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
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam("auth_only", 1)
                .queryParam("display", 0)
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
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret())
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
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR_CODE)) {
            throw new AuthException(AuthToutiaoErrorCode.getErrorCode(getIntValue(object, Keys.ERROR_CODE)).getDesc());
        }
    }
}
