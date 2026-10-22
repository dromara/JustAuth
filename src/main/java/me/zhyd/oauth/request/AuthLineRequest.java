package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthLineScope;
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

import java.util.HashMap;
import java.util.Map;

/**
 * LINE 登录, line.biz
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
public class AuthLineRequest extends AuthDefaultRequest {

    public AuthLineRequest(AuthConfig config) {
        super(config, AuthDefaultSource.LINE);
    }

    public AuthLineRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.LINE, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> params = new HashMap<>();
        params.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2__CODE, authCallback.getCode());
        params.put(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri());
        params.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret());

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        JsonNode accessTokenObject = toNode(response);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC__ID_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2__SCOPE))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = UnifiedHttpClient.getAdapter().get(source.userInfo(), null, new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken())), false).getBody();

        JsonNode userInfoObject = toNode(response);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "userId"))
                .username(getStringValue(userInfoObject, "displayName"))
                .nickname(getStringValue(userInfoObject, "displayName"))
                .avatar(getStringValue(userInfoObject, "pictureUrl"))
                .remark(getStringValue(userInfoObject, "statusMessage"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<?> revoke(AuthToken authToken) {
        Map<String, String> params = new HashMap<>(5);
        params.put(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken());
        params.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret());

        String response = UnifiedHttpClient.getAdapter().post(source.revoke(), params, false).getBody();
        
        JsonNode object = toNode(response);
        // 返回1表示取消授权成功，否则失败
        AuthResponseStatus status = getBooleanValue(object, "revoked") ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        Map<String, String> params = new HashMap<>();
        params.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2__REFRESH_TOKEN);
        params.put(Keys.OAUTH2__REFRESH_TOKEN, oldToken.getRefreshToken());
        params.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret());

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                        .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                        .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                        .scope(getStringValue(accessTokenObject, Keys.OAUTH2__SCOPE))
                        .idToken(getStringValue(accessTokenObject, Keys.OIDC__ID_TOKEN))
                        .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                        .build())
                .build();
    }

    @Override
    public String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam("user", authToken.getUid())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam("nonce", state)
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthLineScope.values())))
                .build();
    }
}
