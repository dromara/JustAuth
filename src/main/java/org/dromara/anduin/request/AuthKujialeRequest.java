package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.scope.AuthKujialeScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

/**
 * 酷家乐授权登录
 *
 * @author shahuang
 * @since 1.11.0
 */
public class AuthKujialeRequest extends AuthDefaultRequest {

    public AuthKujialeRequest(AuthConfig config) {
        super(config, AuthDefaultSource.KUJIALE);
    }

    public AuthKujialeRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.KUJIALE, authStateCache);
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     * 默认只向用户请求用户信息授权
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.11.0
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthKujialeScope.values())))
                .build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        return getAuthToken(response);
    }

    private AuthToken getAuthToken(String response) {
        JsonNode accessTokenObject = checkResponse(response);
        JsonNode resultObject = getObjectNode(accessTokenObject, "d");
        return AuthToken.builder()
                .accessToken(getStringValue(resultObject, "accessToken"))
                .expireIn(getIntValue(resultObject, "expiresIn"))
                .refreshToken(getStringValue(resultObject, "refreshToken"))
                .build();
    }

    private JsonNode checkResponse(String response) {
        JsonNode accessTokenObject = toNode(response);
        if (!"0".equals(getStringValue(accessTokenObject, "c"))) {
            throw new AuthException(getStringValue(accessTokenObject, "m"));
        }
        return accessTokenObject;
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String openId = this.getOpenId(authToken);

        String response = UnifiedHttpClient.getAdapter().get(UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2.OPEN_ID, openId)
                .build()).getBody();

        JsonNode responseObject = toNode(response);
        if (!"0".equals(getStringValue(responseObject, "c"))) {
            throw new AuthException(getStringValue(responseObject, "m"));
        }
        JsonNode userInfoObject = getObjectNode(responseObject, "d");

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .username(getStringValue(userInfoObject, "userName"))
                .nickname(getStringValue(userInfoObject, "userName"))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR))
                .uuid(getStringValue(userInfoObject, "openId"))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 获取酷家乐的openId，此id在当前client范围内可以唯一识别授权用户
     *
     * @param authToken 通过{@link AuthKujialeRequest#getAccessToken(AuthCallback)}获取到的{@code authToken}
     * @return openId
     */
    private String getOpenId(AuthToken authToken) {
        String response = UnifiedHttpClient.getAdapter().get(UrlBuilder.fromBaseUrl("https://oauth.kujiale.com/oauth2/auth/user")
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .build()).getBody();

        JsonNode accessTokenObject = checkResponse(response);

        return getStringValue(accessTokenObject, "d");
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        String response = UnifiedHttpClient.getAdapter().post(refreshTokenUrl(authToken.getRefreshToken())).getBody();

        return AuthResponse.<AuthToken>builder().code(AuthResponseStatus.SUCCESS.getCode()).data(getAuthToken(response)).build();
    }
}
