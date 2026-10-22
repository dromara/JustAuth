package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthGoogleScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.TokenUtils;
import tools.jackson.databind.JsonNode;

/**
 * Google登录
 *
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.3.0
 */
public class AuthGoogleRequest extends AuthDefaultRequest {

    public AuthGoogleRequest(AuthConfig config) {
        super(config, AuthDefaultSource.GOOGLE);
    }

    public AuthGoogleRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.GOOGLE, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2__SCOPE))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC__ID_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));

        String response = UnifiedHttpClient.getAdapter().post(userInfoUrl(authToken), null, httpHeader).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "sub"))
                .username(getStringValue(userInfoObject, Keys.OAUTH2_SCOPE__EMAIL))
                .avatar(getStringValue(userInfoObject, "picture"))
                .nickname(getStringValue(userInfoObject, Keys.NAME))
                .location(getStringValue(userInfoObject, "locale"))
                .email(getStringValue(userInfoObject, Keys.OAUTH2_SCOPE__EMAIL))
                .gender(AuthUserGender.UNKNOWN)
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
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam("access_type", "offline")
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthGoogleScope.values())))
                .queryParam("prompt", "select_account")
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
        return UrlBuilder.fromBaseUrl(source.userInfo()).queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken()).build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR) || containsKey(object, Keys.ERROR_DESCRIPTION)) {
            throw new AuthException(containsKey(object, Keys.ERROR) + ":" + getStringValue(object, Keys.ERROR_DESCRIPTION));
        }
    }
}
