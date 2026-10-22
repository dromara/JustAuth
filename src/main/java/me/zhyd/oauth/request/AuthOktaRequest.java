package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthOktaScope;
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

import java.util.HashMap;
import java.util.Map;

/**
 * Okta 登录
 * <p>
 * https://{domainPrefix}.okta.com/oauth2/default/.well-known/oauth-authorization-server
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
public class AuthOktaRequest extends AuthDefaultRequest {

    public AuthOktaRequest(AuthConfig config) {
        super(config, AuthDefaultSource.OKTA);
    }

    public AuthOktaRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.OKTA, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String tokenUrl = accessTokenUrl(authCallback.getCode());
        return getAuthToken(tokenUrl);
    }

    private AuthToken getAuthToken(String tokenUrl) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));

        String response = UnifiedHttpClient.getAdapter().post(tokenUrl, null, header, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2__SCOPE))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC__ID_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        if (null == authToken.getRefreshToken()) {
            return AuthResponse.<AuthToken>builder()
                    .code(AuthResponseStatus.ILLEGAL_TOKEN.getCode())
                    .msg(AuthResponseStatus.ILLEGAL_TOKEN.getMsg())
                    .build();
        }
        String refreshUrl = refreshTokenUrl(authToken.getRefreshToken());
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(this.getAuthToken(refreshUrl))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));

        String response = UnifiedHttpClient.getAdapter().post(userInfoUrl(authToken), null, header, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        JsonNode address = getObjectNode(userInfoObject, Keys.OAUTH2_SCOPE__ADDRESS);
        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "sub"))
                .username(getStringValue(userInfoObject, Keys.NAME))
                .nickname(getStringValue(userInfoObject, Keys.NICKNAME))
                .email(getStringValue(userInfoObject, Keys.OAUTH2_SCOPE__EMAIL))
                .location(null == address ? null : getStringValue(address, "street_address"))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, "sex")))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<?> revoke(AuthToken authToken) {
        Map<String, String> params = new HashMap<>(4);
        params.put("token", authToken.getAccessToken());
        params.put("token_type_hint", Keys.OAUTH2__ACCESS_TOKEN);

        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));
        UnifiedHttpClient.getAdapter().post(revokeUrl(authToken), params, header, false);
        AuthResponseStatus status = AuthResponseStatus.SUCCESS;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.ERROR_DESCRIPTION));
        }
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(String.format(source.authorize(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam("prompt", "consent")
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthOktaScope.values())))
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
                .build();
    }

    @Override
    public String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(String.format(source.accessToken(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2__CODE, code)
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(String.format(source.refresh(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2__REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2__REFRESH_TOKEN)
                .build();
    }

    @Override
    protected String revokeUrl(AuthToken authToken) {
        return String.format(source.revoke(), config.getDomainPrefix(), config.getAuthServerId());
    }

    @Override
    public String userInfoUrl(AuthToken authToken) {
        return String.format(source.userInfo(), config.getDomainPrefix(), config.getAuthServerId());
    }
}
