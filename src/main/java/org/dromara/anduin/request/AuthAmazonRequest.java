package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthAmazonScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.*;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.PkceUtil;
import org.dromara.anduin.utils.TokenUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * Amazon登录
 * Login with Amazon for Websites Overview： <a href="https://developer.amazon.com/zh/docs/login-with-amazon/register-web.html">...</a>
 * Login with Amazon SDK for JavaScript Reference Guide：<a href="https://developer.amazon.com/zh/docs/login-with-amazon/javascript-sdk-reference.html">...</a>
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
public class AuthAmazonRequest extends AuthDefaultRequest {

    public AuthAmazonRequest(AuthConfig config) {
        super(config, AuthDefaultSource.AMAZON);
    }

    public AuthAmazonRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.AMAZON, authStateCache);
    }

    /**
     * <a href="https://developer.amazon.com/zh/docs/login-with-amazon/authorization-code-grant.html#authorization-request">...</a>
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return String
     */
    @Override
    public String authorize(String state) {
        String realState = getRealState(state);
        UrlBuilder builder = UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthAmazonScope.values())))
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.STATE, realState);

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(realState);
            String codeVerifier = PkceUtil.generateCodeVerifier();
            String codeChallengeMethod = "S256";
            String codeChallenge = PkceUtil.generateCodeChallenge(codeChallengeMethod, codeVerifier);
            builder.queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", codeChallengeMethod);
            // 缓存 codeVerifier
            this.authStateCache.cache(cacheKey, codeVerifier);
        }

        return builder.build();
    }

    /**
     * <a href="https://developer.amazon.com/zh/docs/login-with-amazon/authorization-code-grant.html#access-token-request">...</a>
     *
     * @return access token
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> params = new HashMap<>(9);
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        params.put(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri());
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(authCallback.getState());
            String codeVerifier = this.authStateCache.get(cacheKey);
            params.put("code_verifier", codeVerifier);
        }
        return getToken(params, this.source.accessToken());
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);
        params.put(Keys.OAUTH2.REFRESH_TOKEN, authToken.getRefreshToken());
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(params, this.source.refresh()))
                .build();

    }

    private AuthToken getToken(Map<String, String> param, String url) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.HOST, "api.amazon.com");
        httpHeader.add(HttpConstants.CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8");

        String response = UnifiedHttpClient.getAdapter().post(url, param, httpHeader, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    /**
     * 校验响应内容是否正确
     *
     * @param jsonNode 响应内容
     */
    private void checkResponse(JsonNode jsonNode) {
        if (containsKey(jsonNode, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(jsonNode, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION).concat(" ") + getStringValue(jsonNode, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
    }

    /**
     * <a href="https://developer.amazon.com/zh/docs/login-with-amazon/obtain-customer-profile.html#call-profile-endpoint">...</a>
     *
     * @param authToken token信息
     * @return AuthUser
     */
    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();
        this.checkToken(accessToken);

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.HOST, "api.amazon.com");
        httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(accessToken));

        String response = UnifiedHttpClient.getAdapter().get(this.source.userInfo(), new HashMap<>(0), httpHeader, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.USER_ID))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .source(source.toString())
                .token(authToken)
                .build();
    }

    private void checkToken(String accessToken) {
        String response = UnifiedHttpClient.getAdapter().get("https://api.amazon.com/auth/o2/tokeninfo?access_token=" + HttpUrlEncoding.encode(accessToken)).getBody();
        JsonNode object = toNode(response);
        if (!config.getClientId().equals(getStringValue(object, "aud"))) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_TOKEN);
        }
    }

    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.USERINFO.USER_ID, authToken.getUserId())
                .queryParam(Keys.USERINFO.SCREENNAME, authToken.getScreenName())
                .queryParam("include_entities", true)
                .build();
    }
}
