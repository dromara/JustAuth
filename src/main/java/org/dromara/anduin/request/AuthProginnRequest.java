package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthProginnScope;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

/**
 * 程序员客栈
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.2
 */
public class AuthProginnRequest extends AuthDefaultRequest {

    public AuthProginnRequest(AuthConfig config) {
        super(config, AuthDefaultSource.PROGINN);
    }

    public AuthProginnRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.PROGINN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        String response = UnifiedHttpClient.getAdapter().post(AuthDefaultSource.PROGINN.accessToken(), authorizationCodeRequestParams(authCallback), false).getBody();

        JsonNode accessTokenObject = toNode(response);
        validateResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .uid(getStringValue(accessTokenObject, Keys.USERINFO.UID))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);

        JsonNode userInfoObject = toNode(userInfo);
        validateResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.UID))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR))
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
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthProginnScope.values())))
                .build();
    }
}
