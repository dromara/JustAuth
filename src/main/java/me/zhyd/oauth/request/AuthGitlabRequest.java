package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthGitlabScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.databind.JsonNode;

/**
 * Gitlab登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.11.0
 */
public class AuthGitlabRequest extends AuthDefaultRequest {

    public AuthGitlabRequest(AuthConfig config) {
        super(config, AuthDefaultSource.GITLAB);
    }

    public AuthGitlabRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.GITLAB, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2__SCOPE))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC__ID_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.ID))
                .username(getStringValue(userInfoObject, Keys.USERNAME))
                .nickname(getStringValue(userInfoObject, Keys.NAME))
                .avatar(getStringValue(userInfoObject, Keys.AVATAR_URL))
                .blog(getStringValue(userInfoObject, "web_url"))
                .company(getStringValue(userInfoObject, "organization"))
                .location(getStringValue(userInfoObject, Keys.LOCATION))
                .email(getStringValue(userInfoObject, Keys.OAUTH2_SCOPE__EMAIL))
                .remark(getStringValue(userInfoObject, "bio"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    private void checkResponse(JsonNode object) {
        // oauth/token 验证异常
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.ERROR_DESCRIPTION));
        }
        // user 验证异常
        if (containsKey(object, Keys.MESSAGE)) {
            throw new AuthException(getStringValue(object, Keys.MESSAGE));
        }
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.11.0
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes("+", false, AuthScopeUtils.getDefaultScopes(AuthGitlabScope.values())))
                .build();
    }

}
