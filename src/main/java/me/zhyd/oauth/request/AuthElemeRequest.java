package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.*;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * 饿了么
 * <p>
 * 注：集成的是正式环境，非沙箱环境
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.12.0
 */
public class AuthElemeRequest extends AuthDefaultRequest {

    private static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded;charset=UTF-8";
    private static final String CONTENT_TYPE_JSON = "application/json; charset=utf-8";

    public AuthElemeRequest(AuthConfig config) {
        super(config, AuthDefaultSource.ELEME);
    }

    public AuthElemeRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.ELEME, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(7);
        form.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri());
        form.put(Keys.OAUTH2__CODE, authCallback.getCode());
        form.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);

        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_FORM, this.getRequestId(), true);

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), form, httpHeader, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        Map<String, Object> parameters = new HashMap<>(4);
        // 获取商户账号信息的API接口名称
        String action = "eleme.user.getUser";
        // 时间戳，单位秒。API服务端允许客户端请求最大时间误差为正负5分钟。
        final long timestamp = System.currentTimeMillis();
        // 公共参数
        Map<String, Object> metasHashMap = new HashMap<>(4);
        metasHashMap.put(Keys.VARIANT__APP_KEY, config.getClientId());
        metasHashMap.put("timestamp", timestamp);
        String signature = GlobalAuthUtils.generateElemeSignature(config.getClientId(), config.getClientSecret(), timestamp, action, authToken
                .getAccessToken(), parameters);

        String requestId = this.getRequestId();

        Map<String, Object> paramsMap = new HashMap<>();
        paramsMap.put("nop", "1.0.0");
        paramsMap.put(Keys.ID, requestId);
        paramsMap.put("action", action);
        paramsMap.put("token", authToken.getAccessToken());
        paramsMap.put("metas", metasHashMap);
        paramsMap.put("params", parameters);
        paramsMap.put("signature", signature);

        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_JSON, requestId, false);
        String response = UnifiedHttpClient.getAdapter().post(source.userInfo(), JsonUtils.toJson(paramsMap), httpHeader).getBody();

        JsonNode responseObject = toNode(response);

        // 校验请求
        if (containsKey(responseObject, Keys.NAME)) {
            throw new AuthException(getStringValue(responseObject, Keys.MESSAGE));
        }
        if (containsKey(responseObject, Keys.ERROR) && null != responseObject.get(Keys.ERROR)) {
            JsonNode error = responseObject.get(Keys.ERROR);
            throw new AuthException(getStringValue(error, Keys.MESSAGE));
        }

        JsonNode userInfoObject = getObjectNode(responseObject, Keys.RESULT);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "userId"))
                .username(getStringValue(userInfoObject, "userName"))
                .nickname(getStringValue(userInfoObject, "userName"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_FORM, this.getRequestId(), true);

        Map<String, String> params = new HashMap<>(4);
        params.put(Keys.OAUTH2__REFRESH_TOKEN, oldToken.getRefreshToken());
        params.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2__REFRESH_TOKEN);

        String response = UnifiedHttpClient.getAdapter().post(source.refresh(), params, httpHeader, false).getBody();

        JsonNode refreshTokenObject = toNode(response);

        this.checkResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(refreshTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                        .expireIn(getIntValue(refreshTokenObject, Keys.OAUTH2__EXPIRES_IN))
                        .refreshToken(getStringValue(refreshTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                        .tokenType(getStringValue(refreshTokenObject, Keys.OAUTH2__TOKEN_TYPE))
                        .build())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state)).queryParam(Keys.OAUTH2__SCOPE, "all").build();
    }

    private HttpHeader buildHeader(String contentType, String requestId, boolean auth) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.ACCEPT, "text/xml,text/javascript,text/html");
        httpHeader.add(HttpHeaders.CONTENT_TYPE, contentType);
        httpHeader.add(HttpHeaders.ACCEPT_ENCODING, "gzip");
        httpHeader.add(HttpHeaders.USER_AGENT, "eleme-openapi-java-sdk");
        httpHeader.add("x-eleme-requestid", requestId);
        if (auth) {
            httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));
        }
        return httpHeader;
    }

    private String getRequestId() {
        return (UuidUtils.getUUID() + "|" + System.currentTimeMillis()).toUpperCase();
    }

    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.ERROR_DESCRIPTION));
        }
    }

}
