package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthGithubScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.GlobalAuthUtils;
import org.dromara.anduin.utils.TokenUtils;
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

        this.checkResponse(res.containsKey(Keys.RESPONSE_FIELDS.ERROR), res.get(Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));

        return AuthToken.builder()
                .accessToken(res.get(Keys.OAUTH2.ACCESS_TOKEN))
                .scope(res.get(Keys.OAUTH2.SCOPE))
                .tokenType(res.get(Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.AUTHORIZATION, TokenUtils.token(authToken.getAccessToken()));
        String response = UnifiedHttpClient.getAdapter().get(UrlBuilder.fromBaseUrl(source.userInfo()).build(), null, header, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(containsKey(userInfoObject, Keys.RESPONSE_FIELDS.ERROR), getStringValue(userInfoObject, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .username(getStringValue(userInfoObject, "login"))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR_URL))
                .blog(getStringValue(userInfoObject, "blog"))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .company(getStringValue(userInfoObject, Keys.USERINFO.COMPANY))
                .location(getStringValue(userInfoObject, Keys.USERINFO.LOCATION))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
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
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthGithubScope.values())))
                .build();
    }

}
