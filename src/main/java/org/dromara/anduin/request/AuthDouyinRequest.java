package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthDouyinScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.JsonNodeUtils;
import tools.jackson.databind.JsonNode;


/**
 * 抖音登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.4.0
 */
public class AuthDouyinRequest extends AuthDefaultRequest {

    private static final String CLIENT_KEY = "client_key";

    public AuthDouyinRequest(AuthConfig config) {
        super(config, AuthDefaultSource.DOUYIN);
    }

    public AuthDouyinRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.DOUYIN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return this.getToken(accessTokenUrl(authCallback.getCode()));
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);
        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);
        JsonNode userInfoDataObject = JsonNodeUtils.findObjectNode(userInfoObject, Keys.RESPONSE_FIELDS.DATA);
        authToken.setUnionId(getStringValue(userInfoDataObject, Keys.USERINFO.UNION_ID));
        return AuthUser.builder()
                .rawUserInfo(userInfoDataObject)
                .uuid(getStringValue(userInfoDataObject, Keys.USERINFO.UNION_ID))
                .username(getStringValue(userInfoDataObject, Keys.USERINFO.NICKNAME))
                .nickname(getStringValue(userInfoDataObject, Keys.USERINFO.NICKNAME))
                .avatar(getStringValue(userInfoDataObject, Keys.USERINFO.AVATAR))
                .remark(getStringValue(userInfoDataObject, Keys.USERINFO.DESCRIPTION))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoDataObject, Keys.USERINFO.GENDER)))
                .location(String.format("%s %s %s", getStringValue(userInfoDataObject, Keys.USERINFO.COUNTRY), getStringValue(userInfoDataObject, Keys.USERINFO.PROVINCE), getStringValue(userInfoDataObject, Keys.USERINFO.CITY)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(refreshTokenUrl(oldToken.getRefreshToken())))
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        String message = getStringValue(object, Keys.USERINFO.MESSAGE);
        JsonNode data = getDataNode(object);
        int errorCode = getIntValue(data, Keys.RESPONSE_FIELDS.ERROR_CODE);
        if (Keys.RESPONSE_FIELDS.ERROR.equals(message) || errorCode != 0) {
            throw new AuthException(errorCode, getStringValue(data, Keys.RESPONSE_FIELDS.DESCRIPTION));
        }
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl) {
        String response = UnifiedHttpClient.getAdapter().post(accessTokenUrl).getBody();
        JsonNode object = toNode(response);
        this.checkResponse(object);

        JsonNode accessTokenObject = getDataNode(object);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .openId(getStringValue(accessTokenObject, Keys.OAUTH2.OPEN_ID))
                .refreshTokenExpireIn(getIntValue(accessTokenObject, "refresh_expires_in"))
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
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(CLIENT_KEY, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthDouyinScope.values())))
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code oauth的授权码
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(CLIENT_KEY, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken oauth返回的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2.OPEN_ID, authToken.getOpenId())
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param refreshToken oauth返回的refreshtoken
     * @return 返回获取accessToken的url
     */
    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam(CLIENT_KEY, config.getClientId())
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
                .build();
    }
}
