package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.scope.AuthFigmaScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.TokenUtils;
import tools.jackson.databind.JsonNode;

/**
 * Figma登录
 *
 * @author xiangqian
 * @since 1.16.6
 */
public class AuthFigmaRequest extends AuthDefaultRequest {
    public AuthFigmaRequest(AuthConfig config) {
        super(config, AuthDefaultSource.FIGMA);
    }

    public AuthFigmaRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.FIGMA, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthFigmaScope.values())))
                .build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));

        String response = UnifiedHttpClient.getAdapter().post(super.accessTokenUrl(authCallback.getCode()), null, header, true).getBody();

        JsonNode accessTokenObject = toNode(response);

        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .userId(getStringValue(accessTokenObject, Keys.USERINFO.USER_ID))
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        HttpHeader header = new HttpHeader().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
        String response = UnifiedHttpClient.getAdapter().post(this.refreshTokenUrl(authToken.getRefreshToken()), null, header, false).getBody();

        JsonNode refreshTokenObject = toNode(response);

        this.checkResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(refreshTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                        .expireIn(getIntValue(refreshTokenObject, Keys.OAUTH2.EXPIRES_IN))
                        .refreshToken(getStringValue(refreshTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                        .scope(getStringValue(refreshTokenObject, Keys.OAUTH2.SCOPE))
                        .openId(getStringValue(refreshTokenObject, Keys.OAUTH2.OPEN_ID))
                        .build())
                .build();

    }

    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader().add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));
        String response = UnifiedHttpClient.getAdapter().get(super.userInfoUrl(authToken), null, header, false).getBody();
        JsonNode userInfoObject = toNode(response);

        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .username(getStringValue(userInfoObject, "handle"))
                .avatar(getStringValue(userInfoObject, "img_url"))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .token(authToken)
                .source(source.toString())
                .build();
    }


    /**
     * 校验响应结果
     *
     * @param object 接口返回的结果
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERROR) + ":" + getStringValue(object, Keys.USERINFO.MESSAGE));
        }
    }
}
