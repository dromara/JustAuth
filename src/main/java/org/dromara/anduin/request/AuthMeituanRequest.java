package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import tools.jackson.databind.JsonNode;

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
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return generateToken(accessTokenObject);
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doPostUserInfo(authToken);

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
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        String response = doPostRefreshToken(authToken.getRefreshToken());

        JsonNode refreshTokenObject = toNode(response);
        this.checkResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(generateToken(refreshTokenObject))
                .build();
    }

    private AuthToken generateToken(JsonNode jsonNode) {
        return AuthToken.builder()
                .accessToken(getStringValue(jsonNode, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(jsonNode, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(jsonNode, Keys.OAUTH2.REFRESH_TOKEN))
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

    @Override
    public String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.APP_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .build();
    }

    @Override
    public String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam(Keys.OAUTH2.APP_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
                .build();
    }

    @Override
    public String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.APP_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .build();


    }
}
