package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthGithubScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.TokenUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.databind.JsonNode;

import java.util.Map;

/**
 * Github登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthGithubRequest extends AuthDefaultRequest {

    public AuthGithubRequest(AuthConfig config) {
        super(config, AuthDefaultSource.GITHUB);
    }

    public AuthGithubRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.GITHUB, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        Map<String, String> res = GlobalAuthUtils.parseStringToMap(response);

        this.checkResponse(res.containsKey(Keys.ERROR), res.get(Keys.ERROR_DESCRIPTION));

        return AuthToken.builder()
                .accessToken(res.get(Keys.OAUTH2__ACCESS_TOKEN))
                .scope(res.get(Keys.OAUTH2__SCOPE))
                .tokenType(res.get(Keys.OAUTH2__TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.AUTHORIZATION, TokenUtils.token(authToken.getAccessToken()));
        String response = UnifiedHttpClient.getAdapter().get(UrlBuilder.fromBaseUrl(source.userInfo()).build(), null, header, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(containsKey(userInfoObject, Keys.ERROR), getStringValue(userInfoObject, Keys.ERROR_DESCRIPTION));

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.ID))
                .username(getStringValue(userInfoObject, "login"))
                .avatar(getStringValue(userInfoObject, Keys.AVATAR_URL))
                .blog(getStringValue(userInfoObject, "blog"))
                .nickname(getStringValue(userInfoObject, Keys.NAME))
                .company(getStringValue(userInfoObject, Keys.COMPANY))
                .location(getStringValue(userInfoObject, Keys.LOCATION))
                .email(getStringValue(userInfoObject, Keys.OAUTH2_SCOPE__EMAIL))
                .remark(getStringValue(userInfoObject, "bio"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    private void checkResponse(boolean error, String errorDescription) {
        if (error) {
            throw new AuthException(errorDescription);
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
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthGithubScope.values())))
                .build();
    }

}
