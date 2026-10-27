package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthOktaScope;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AccessTokenUtils;
import org.dromara.anduin.utils.AuthScopeUtils;
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
        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
        header.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
        header.add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.basic(config.getClientId(), config.getClientSecret()));

        String response = UnifiedHttpClient.getAdapter().post(tokenUrl, null, header, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        validateResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC.ID_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
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
                .add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.bearer(authToken.getAccessToken()));

        String response = UnifiedHttpClient.getAdapter().post(userInfoUrl(authToken), null, header, false).getBody();

        JsonNode userInfoObject = toNode(response);
        validateResponse(userInfoObject);

        JsonNode address = getObjectNode(userInfoObject, Keys.USERINFO.ADDRESS);
        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.SUB))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .location(null == address ? null : getStringValue(address, "street_address"))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.USERINFO.SEX)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<?> revoke(AuthToken authToken) {
        Map<String, String> params = new HashMap<>(4);
        params.put("token", authToken.getAccessToken());
        params.put("token_type_hint", Keys.OAUTH2.ACCESS_TOKEN);

        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.basic(config.getClientId(), config.getClientSecret()));
        UnifiedHttpClient.getAdapter().post(revokeUrl(authToken), params, header, false);
        AuthResponseStatus status = AuthResponseStatus.SUCCESS;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(String.format(source.authorize(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam("prompt", "consent")
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthOktaScope.values())))
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }

    @Override
    public String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(String.format(source.accessToken(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(String.format(source.refresh(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
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
