package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.GlobalAuthUtils;
import org.dromara.anduin.utils.JsonUtils;
import org.dromara.anduin.utils.TokenUtils;
import org.dromara.anduin.utils.UuidUtils;
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
        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri());
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);

        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_FORM, this.getRequestId(), true);

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, httpHeader, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        validateResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
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
        metasHashMap.put(Keys.OAUTH2.APP_KEY, config.getClientId());
        metasHashMap.put("timestamp", timestamp);
        String signature = GlobalAuthUtils.generateElemeSignature(config.getClientId(), config.getClientSecret(), timestamp, action, authToken
                .getAccessToken(), parameters);

        String requestId = this.getRequestId();

        Map<String, Object> paramsMap = new HashMap<>();
        paramsMap.put("nop", "1.0.0");
        paramsMap.put(Keys.USERINFO.ID, requestId);
        paramsMap.put("action", action);
        paramsMap.put("token", authToken.getAccessToken());
        paramsMap.put("metas", metasHashMap);
        paramsMap.put("params", parameters);
        paramsMap.put("signature", signature);

        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_JSON, requestId, false);
        String response = UnifiedHttpClient.getAdapter().post(source.userInfo(), JsonUtils.toJson(paramsMap), httpHeader).getBody();

        JsonNode responseObject = toNode(response);

        // 校验请求
        if (containsKey(responseObject, Keys.USERINFO.NAME)) {
            throw new AuthException(getStringValue(responseObject, Keys.USERINFO.MESSAGE));
        }
        if (containsKey(responseObject, Keys.RESPONSE_FIELDS.ERROR) && null != responseObject.get(Keys.RESPONSE_FIELDS.ERROR)) {
            JsonNode error = responseObject.get(Keys.RESPONSE_FIELDS.ERROR);
            throw new AuthException(getStringValue(error, Keys.USERINFO.MESSAGE));
        }

        JsonNode userInfoObject = getObjectNode(responseObject, Keys.RESPONSE_FIELDS.RESULT);

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
        params.put(Keys.OAUTH2.REFRESH_TOKEN, oldToken.getRefreshToken());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);

        String response = UnifiedHttpClient.getAdapter().post(source.refresh(), params, httpHeader, false).getBody();

        JsonNode refreshTokenObject = toNode(response);
        validateResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(refreshTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                        .expireIn(getIntValue(refreshTokenObject, Keys.OAUTH2.EXPIRES_IN))
                        .refreshToken(getStringValue(refreshTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                        .tokenType(getStringValue(refreshTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                        .build())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state)).queryParam(Keys.OAUTH2.SCOPE, "all").build();
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
}
