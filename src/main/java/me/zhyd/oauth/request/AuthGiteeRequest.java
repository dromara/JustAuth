package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthGiteeScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.databind.JsonNode;

/**
 * Gitee登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthGiteeRequest extends AuthDefaultRequest {

    public AuthGiteeRequest(AuthConfig config) {
        super(config, AuthDefaultSource.GITEE);
    }

    public AuthGiteeRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.GITEE, authStateCache);
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
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);
        JsonNode object = toNode(userInfo);
        this.checkResponse(object);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(getStringValue(object, Keys.ID))
                .username(getStringValue(object, "login"))
                .avatar(getStringValue(object, Keys.AVATAR_URL))
                .blog(getStringValue(object, "blog"))
                .nickname(getStringValue(object, Keys.NAME))
                .company(getStringValue(object, Keys.COMPANY))
                .location(getStringValue(object, Keys.OAUTH2_SCOPE__ADDRESS))
                .email(getStringValue(object, Keys.OAUTH2_SCOPE__EMAIL))
                .remark(getStringValue(object, "bio"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.ERROR_DESCRIPTION));
        }
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthGiteeScope.values())))
                .build();
    }
}
