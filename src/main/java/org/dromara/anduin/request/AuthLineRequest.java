package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthLineScope;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.TokenUtils;
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

        Map<String, String> params = authorizationCodeRequestParams(authCallback);

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        JsonNode accessTokenObject = toNode(response);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC.ID_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
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
                .username(getStringValue(userInfoObject, Keys.USERINFO.DISPLAY_NAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.DISPLAY_NAME))
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
        params.put(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken());
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());

        String response = UnifiedHttpClient.getAdapter().post(source.revoke(), params, false).getBody();

        JsonNode object = toNode(response);
        // 返回1表示取消授权成功，否则失败
        AuthResponseStatus status = getBooleanValue(object, "revoked") ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        Map<String, String> params = new HashMap<>();
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);
        params.put(Keys.OAUTH2.REFRESH_TOKEN, oldToken.getRefreshToken());
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                        .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                        .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                        .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                        .idToken(getStringValue(accessTokenObject, Keys.OIDC.ID_TOKEN))
                        .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                        .build())
                .build();
    }

    @Override
    public String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.USERINFO.USER, authToken.getUid())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam("nonce", state)
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthLineScope.values())))
                .build();
    }
}
