package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.AdapterHttpResponse;
import me.zhyd.oauth.http.HttpClientAdapter;
import me.zhyd.oauth.http.HttpConfig;
import me.zhyd.oauth.http.HttpConstants;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.adapter.JdkHttpAdapter;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.utils.JsonUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;

/**
 * 支持私有化部署的 OAuth 授权请求基类。
 *
 * @author AprilWind
 */
abstract class AbstractAuthServerRequest extends AuthDefaultRequest {

    protected AbstractAuthServerRequest(AuthConfig config, AuthSource source) {
        super(config, source);
    }

    protected AbstractAuthServerRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        super(config, source, authStateCache);
    }

    /**
     * 将 OAuth 标准字段映射为授权令牌。
     *
     * @param object 令牌响应
     * @return 授权令牌
     */
    protected AuthToken buildToken(JsonNode object) {
        return AuthToken.builder()
                .accessToken(stringValue(object, Keys.OAUTH2__ACCESS_TOKEN))
                .refreshToken(stringValue(object, Keys.OAUTH2__REFRESH_TOKEN))
                .idToken(stringValue(object, Keys.OIDC__ID_TOKEN))
                .tokenType(stringValue(object, Keys.OAUTH2__TOKEN_TYPE))
                .scope(stringValue(object, Keys.OAUTH2__SCOPE))
                .expireIn(getIntValue(object, Keys.OAUTH2__EXPIRES_IN))
                .build();
    }

    /**
     * 检查 OAuth 错误及平台错误信息。
     *
     * @param object 响应对象
     */
    protected void checkResponse(JsonNode object) {
        if (object == null) {
            throw new AuthException("Empty response from OAuth server");
        }
        if (object.has(Keys.ERROR)) {
            String message = stringValue(object, Keys.ERROR_DESCRIPTION);
            throw new AuthException(message == null ? stringValue(object, Keys.ERROR) : message);
        }
        if (object.has(Keys.MESSAGE)) {
            throw new AuthException(stringValue(object, Keys.MESSAGE));
        }
    }

    /**
     * 解析响应并保留非成功 HTTP 响应中的 OAuth 错误信息。
     *
     * @param response HTTP 响应
     * @return 有效 JSON 对象
     */
    protected JsonNode parseResponse(AdapterHttpResponse response) {
        if (response == null) {
            throw new AuthException("Empty response from OAuth server");
        }
        String body = response.getBody();
        JsonNode object = null;
        if (body != null && !body.isBlank()) {
            try {
                object = JsonUtils.getObjectMapper().readTree(body);
            } catch (JacksonException exception) {
                if (response.isSuccess()) {
                    throw new AuthException("Invalid JSON response from OAuth server", exception);
                }
            }
        }
        if (object != null && object.isObject()) {
            checkResponse(object);
        }
        if (!response.isSuccess()) {
            String message = body;
            if (message == null || message.isBlank()) {
                message = response.getError();
            }
            if (message == null || message.isBlank()) {
                message = "OAuth server returned HTTP " + response.getCode();
            }
            throw new AuthException(message);
        }
        if (object == null || !object.isObject()) {
            throw new AuthException("Invalid or empty response from OAuth server");
        }
        return object;
    }

    /**
     * 读取标量字段，兼容用户标识为数字的平台。
     *
     * @param object 响应对象
     * @param key 字段名称
     * @return 字段文本，不存在或非标量时返回 null
     */
    protected String stringValue(JsonNode object, String key) {
        JsonNode value = object.get(key);
        return value == null || value.isNull() || value.isContainer() ? null : value.asString();
    }

    /**
     * 按顺序读取第一个非空字段。
     *
     * @param object 响应对象
     * @param keys 候选字段
     * @return 首个非空字段文本
     */
    protected String firstNotEmpty(JsonNode object, String... keys) {
        for (String key : keys) {
            String value = stringValue(object, key);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    /**
     * 使用请求配置中的超时和代理；未配置时沿用统一客户端。
     *
     * @return HTTP 适配器
     */
    protected HttpClientAdapter httpClient() {
        HttpConfig httpConfig = config.getHttpConfig();
        if (httpConfig == null) {
            return UnifiedHttpClient.getAdapter();
        }
        if (httpConfig.getTimeout() <= 0) {
            httpConfig = new HttpConfig(HttpConstants.DEFAULT_TIMEOUT, httpConfig.getProxy());
        }
        return new JdkHttpAdapter(httpConfig);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(serverEndpoint(source.authorize()))
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
                .build();
    }

    @Override
    protected String accessTokenUrl(String code) {
        return tokenEndpoint();
    }

    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return serverEndpoint(source.userInfo());
    }

    protected final String serverEndpoint(String endpointTemplate) {
        return String.format(endpointTemplate, normalizeServerUrl(config.getServerUrl()));
    }

    protected final String tokenEndpoint() {
        return serverEndpoint(source.accessToken());
    }

    private String normalizeServerUrl(String serverUrl) {
        int end = serverUrl.length();
        while (end > 0 && serverUrl.charAt(end - 1) == '/') {
            end--;
        }
        return serverUrl.substring(0, end);
    }
}
