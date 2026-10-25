package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthRenrenScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpUrlEncoding;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

import java.util.Objects;

import static me.zhyd.oauth.config.AuthDefaultSource.RENREN;
import static me.zhyd.oauth.enums.AuthResponseStatus.SUCCESS;

/**
 * 人人登录
 *
 * @author hongwei.peng (pengisgood(at)gmail(dot)com)
 * @since 1.9.0
 */
public class AuthRenrenRequest extends AuthDefaultRequest {

    public AuthRenrenRequest(AuthConfig config) {
        super(config, RENREN);
    }

    public AuthRenrenRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, RENREN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return this.getToken(accessTokenUrl(authCallback.getCode()));
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);

        JsonNode object = toNode(response);
        JsonNode userInfoObject = getObjectNode(object, "response");

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .avatar(getAvatarUrl(userInfoObject))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .company(getCompany(userInfoObject))
                .gender(getGender(userInfoObject))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        return AuthResponse.<AuthToken>builder()
                .code(SUCCESS.getCode())
                .data(getToken(this.refreshTokenUrl(authToken.getRefreshToken())))
                .build();
    }

    private AuthToken getToken(String url) {
        String response = UnifiedHttpClient.getAdapter().post(url).getBody();
        JsonNode accessTokenObject = toNode(response);
        if (containsKey(accessTokenObject, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException("Failed to get token from Renren: " + accessTokenObject.toString());
        }

        JsonNode userObject = getObjectNode(accessTokenObject, Keys.USERINFO.USER);

        return AuthToken.builder()
                .accessToken(HttpUrlEncoding.encode(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN)))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(HttpUrlEncoding.encode(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN)))
                .openId(getStringValue(userObject, Keys.USERINFO.ID))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    private String getAvatarUrl(JsonNode userObj) {
        JsonNode jsonArray = getArrayNode(userObj, Keys.USERINFO.AVATAR);
        if (Objects.isNull(jsonArray) || jsonArray.isEmpty()) {
            return null;
        }
        return getStringValue(jsonArray.asArray().get(0), Keys.USERINFO.URL);
    }

    private AuthUserGender getGender(JsonNode userObj) {
        JsonNode basicInformation = getObjectNode(userObj, "basicInformation");
        if (Objects.isNull(basicInformation)) {
            return AuthUserGender.UNKNOWN;
        }
        return AuthUserGender.getRealGender(getStringValue(basicInformation, Keys.USERINFO.SEX));
    }

    private String getCompany(JsonNode userObj) {
        JsonNode jsonArray = getArrayNode(userObj, "work");
        if (Objects.isNull(jsonArray) || jsonArray.isEmpty()) {
            return null;
        }
        return getStringValue(jsonArray.asArray().get(0), Keys.USERINFO.NAME);
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
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("userId", authToken.getOpenId())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthRenrenScope.values())))
                .build();
    }
}
