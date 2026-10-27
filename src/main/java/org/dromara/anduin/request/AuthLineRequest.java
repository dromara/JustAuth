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
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AccessTokenUtils;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

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
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);

        return generateToken(accessTokenObject);
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {

        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
        header.add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.bearer(authToken.getAccessToken()));

        String response = doGetUserInfo(authToken, header);

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
        String response = doPostRevoke(authToken);

        JsonNode object = toNode(response);
        // 返回1表示取消授权成功，否则失败
        AuthResponseStatus status = getBooleanValue(object, "revoked") ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        String response = doPostRefreshToken(oldToken.getRefreshToken());

        JsonNode refreshTokenObject = toNode(response);
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
                .scope(getStringValue(jsonNode, Keys.OAUTH2.SCOPE))
                .idToken(getStringValue(jsonNode, Keys.OIDC.ID_TOKEN))
                .tokenType(getStringValue(jsonNode, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam("nonce", state)
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthLineScope.values())))
                .build();
    }

    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .build();
    }

    @Override
    public String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.USERINFO.USER, authToken.getUid())
                .build();
    }

    @Override
    public String revokeUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.revoke())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .build();
    }
}
