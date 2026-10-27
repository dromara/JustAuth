package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthGoogleScope;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AccessTokenUtils;
import org.dromara.anduin.utils.AuthScopeUtils;
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
        validateResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC.ID_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.bearer(authToken.getAccessToken()));

        String response = UnifiedHttpClient.getAdapter().post(userInfoUrl(authToken), null, header).getBody();

        JsonNode userInfoObject = toNode(response);
        validateResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.SUB))
                .username(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.PICTURE))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .location(getStringValue(userInfoObject, "locale"))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
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
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthGoogleScope.values())))
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
        return UrlBuilder.fromBaseUrl(source.userInfo()).queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken()).build();
    }
}
