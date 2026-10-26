package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * 美团登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.12.0
 */
public class AuthMeituanRequest extends AuthDefaultRequest {

    public AuthMeituanRequest(AuthConfig config) {
        super(config, AuthDefaultSource.MEITUAN);
    }

    public AuthMeituanRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.MEITUAN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.APP_ID, config.getClientId());
        params.put(Keys.OAUTH2.SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {

        Map<String, String> params = new HashMap<>(5);
        params.put(Keys.OAUTH2.APP_ID, config.getClientId());
        params.put(Keys.OAUTH2.SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken());

        String response = UnifiedHttpClient.getAdapter().post(source.userInfo(), params, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.OAUTH2.SCOPES.OPENID))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {

        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.APP_ID, config.getClientId());
        params.put(Keys.OAUTH2.SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2.REFRESH_TOKEN, oldToken.getRefreshToken());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);

        String response = UnifiedHttpClient.getAdapter().post(source.refresh(), params, false).getBody();

        JsonNode refreshTokenObject = toNode(response);
        this.checkResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(refreshTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                        .expireIn(getIntValue(refreshTokenObject, Keys.OAUTH2.EXPIRES_IN))
                        .refreshToken(getStringValue(refreshTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                        .build())
                .build();
    }

    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR_CODE)) {
            throw new AuthException(getStringValue(object, "erroe_msg"));
        }
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, "")
                .build();
    }

}
