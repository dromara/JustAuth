package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthAmazonScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpConstants;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.HttpUrlEncoding;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.PkceUtil;
import me.zhyd.oauth.utils.TokenUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Amazon登录
 * Login with Amazon for Websites Overview： https://developer.amazon.com/zh/docs/login-with-amazon/register-web.html
 * Login with Amazon SDK for JavaScript Reference Guide：https://developer.amazon.com/zh/docs/login-with-amazon/javascript-sdk-reference.html
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
     * https://developer.amazon.com/zh/docs/login-with-amazon/authorization-code-grant.html#authorization-request
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return String
     */
    @Override
    public String authorize(String state) {
        String realState = getRealState(state);
        UrlBuilder builder = UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthAmazonScope.values())))
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.OAUTH2__STATE, realState);

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(realState);
            String codeVerifier = PkceUtil.generateCodeVerifier();
            String codeChallengeMethod = "S256";
            String codeChallenge = PkceUtil.generateCodeChallenge(codeChallengeMethod, codeVerifier);
            builder.queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", codeChallengeMethod);
            // 缓存 codeVerifier 十分钟
            this.authStateCache.cache(cacheKey, codeVerifier, TimeUnit.MINUTES.toMillis(10));
        }

        return builder.build();
    }

    /**
     * https://developer.amazon.com/zh/docs/login-with-amazon/authorization-code-grant.html#access-token-request
     *
     * @return access token
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(9);
        form.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        form.put(Keys.OAUTH2__CODE, authCallback.getCode());
        form.put(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri());
        form.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret());

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(authCallback.getState());
            String codeVerifier = this.authStateCache.get(cacheKey);
            form.put("code_verifier", codeVerifier);
        }
        return getToken(form, this.source.accessToken());
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        Map<String, String> form = new HashMap<>(7);
        form.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2__REFRESH_TOKEN);
        form.put(Keys.OAUTH2__REFRESH_TOKEN, authToken.getRefreshToken());
        form.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret());
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(form, this.source.refresh()))
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
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .build();
    }

    /**
     * 校验响应内容是否正确
     *
     * @param jsonNode 响应内容
     */
    private void checkResponse(JsonNode jsonNode) {
        if (containsKey(jsonNode, Keys.ERROR)) {
            throw new AuthException(getStringValue(jsonNode, Keys.ERROR_DESCRIPTION).concat(" ") + getStringValue(jsonNode, Keys.ERROR_DESCRIPTION));
        }
    }

    /**
     * https://developer.amazon.com/zh/docs/login-with-amazon/obtain-customer-profile.html#call-profile-endpoint
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
        String userInfo = UnifiedHttpClient.getAdapter().get(this.source.userInfo(), new HashMap<>(0), httpHeader, false).getBody();
        JsonNode userInfoObject = toNode(userInfo);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.VARIANT__USER_ID))
                .username(getStringValue(userInfoObject, Keys.NAME))
                .nickname(getStringValue(userInfoObject, Keys.NAME))
                .email(getStringValue(userInfoObject, Keys.OAUTH2_SCOPE__EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .source(source.toString())
                .token(authToken)
                .build();
    }

    private void checkToken(String accessToken) {
        String tokenInfo = UnifiedHttpClient.getAdapter().get("https://api.amazon.com/auth/o2/tokeninfo?access_token=" + HttpUrlEncoding.encode(accessToken)).getBody();
        JSONObject jsonObject = JSONObject.parseObject(tokenInfo);
        if (!config.getClientId().equals(jsonObject.getString("aud"))) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_TOKEN);
        }
    }

    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.VARIANT__USER_ID, authToken.getUserId())
                .queryParam("screen_name", authToken.getScreenName())
                .queryParam("include_entities", true)
                .build();
    }
}
