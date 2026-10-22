package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthDouyinScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.JsonNodeUtils;
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
        JsonNode userInfoDataObject = JsonNodeUtils.findObjectNode(userInfoObject, Keys.DATA);
        authToken.setUnionId(getStringValue(userInfoDataObject, Keys.VARIANT__UNION_ID));
        return AuthUser.builder()
                .rawUserInfo(userInfoDataObject)
                .uuid(getStringValue(userInfoDataObject, Keys.VARIANT__UNION_ID))
                .username(getStringValue(userInfoDataObject, Keys.NICKNAME))
                .nickname(getStringValue(userInfoDataObject, Keys.NICKNAME))
                .avatar(getStringValue(userInfoDataObject, Keys.AVATAR))
                .remark(getStringValue(userInfoDataObject, Keys.DESCRIPTION))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoDataObject, Keys.GENDER)))
                .location(String.format("%s %s %s", getStringValue(userInfoDataObject, "country"), getStringValue(userInfoDataObject, "province"), getStringValue(userInfoDataObject, "city")))
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
        String message = getStringValue(object, Keys.MESSAGE);
        JsonNode data = getDataNode(object);
        int errorCode = getIntValue(data, Keys.ERROR_CODE);
        if (Keys.ERROR.equals(message) || errorCode != 0) {
            throw new AuthException(errorCode, getStringValue(data, Keys.DESCRIPTION));
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
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2__SCOPE))
                .openId(getStringValue(accessTokenObject, Keys.VARIANT__OPEN_ID))
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
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(CLIENT_KEY, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthDouyinScope.values())))
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
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
                .queryParam(Keys.OAUTH2__CODE, code)
                .queryParam(CLIENT_KEY, config.getClientId())
                .queryParam(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
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
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.VARIANT__OPEN_ID, authToken.getOpenId())
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
                .queryParam(Keys.OAUTH2__REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2__REFRESH_TOKEN)
                .build();
    }
}
