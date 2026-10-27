package org.dromara.anduin.request;

import org.apache.commons.lang3.StringUtils;
import org.dromara.anduin.cache.AuthDefaultStateCache;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpUrlEncoding;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.log.Log;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthChecker;
import org.dromara.anduin.utils.JsonNodeUtils;
import org.dromara.anduin.utils.JsonUtils;
import org.dromara.anduin.utils.UuidUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 默认的request处理类
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.0.0
 */
public abstract class AuthDefaultRequest implements AuthRequest {
    protected AuthConfig config;
    protected AuthSource source;
    protected AuthStateCache authStateCache;

    protected AuthDefaultRequest(AuthConfig config, AuthSource source) {
        this(config, source, AuthDefaultStateCache.INSTANCE);
    }

    protected AuthDefaultRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        this.config = config;
        this.source = source;
        this.authStateCache = authStateCache;
        if (!AuthChecker.isSupportedAuth(config, source)) {
            throw new AuthException(AuthResponseStatus.PARAMETER_INCOMPLETE, source);
        }
        // 校验配置合法性
        this.checkConfig(config);
    }

    /**
     * 将 JSON 字符串转换为 {@link JsonNode}
     *
     * @param json JSON 字符串
     * @return JSON 节点 {@link JsonNode}
     */
    protected JsonNode toNode(String json) {
        return JsonUtils.toNode(json);
    }

    /**
     * 获取 {@link JsonNode} 中指定的对象类型数据节点
     *
     * @param jsonNode Node {@link JsonNode}
     * @param key      数据节点对应的 Key 值
     * @return 数据节点 {@link JsonNode}
     */
    protected JsonNode getObjectNode(JsonNode jsonNode, String key) {
        return JsonNodeUtils.findObjectNode(jsonNode, key);
    }

    /**
     * 获取 {@link JsonNode} 中指定的数组类型数据节点
     *
     * @param jsonNode Node {@link JsonNode}
     * @param key      数据节点对应的 Key 值
     * @return 数据节点 {@link JsonNode}
     */
    protected JsonNode getArrayNode(JsonNode jsonNode, String key) {
        return JsonNodeUtils.findArrayNode(jsonNode, key);
    }

    /**
     * 获取 {@link JsonNode} 中 data 属性对应的数据节点
     *
     * @param jsonNode Node {@link JsonNode}
     * @return 数据节点 {@link JsonNode}
     */
    protected JsonNode getDataNode(JsonNode jsonNode) {
        return getObjectNode(jsonNode, Keys.RESPONSE_FIELDS.DATA);
    }

    /**
     * 获取 {@link JsonNode} 中指定的 String 类型值
     *
     * @param jsonNode Node {@link JsonNode}
     * @param key      数据节点对应的 Key 值
     * @return 字符串值
     */
    protected String getStringValue(JsonNode jsonNode, String key) {
        return JsonNodeUtils.findStringValue(jsonNode, key);
    }

    /**
     * 获取 {@link JsonNode} 中指定的 Boolean 类型值
     *
     * @param jsonNode Node {@link JsonNode}
     * @param key      数据节点对应的 Key 值
     * @return 布尔值
     */
    protected boolean getBooleanValue(JsonNode jsonNode, String key) {
        return JsonNodeUtils.findBooleanValue(jsonNode, key);
    }

    /**
     * 获取 {@link JsonNode} 中指定的 Boolean 类型值
     *
     * @param jsonNode Node {@link JsonNode}
     * @param key      数据节点对应的 Key 值
     * @return 整型值
     */
    protected int getIntValue(JsonNode jsonNode, String key) {
        return JsonNodeUtils.findIntValue(jsonNode, key);
    }

    /**
     * 获取 {@link JsonNode} 中指定的 Long 类型值
     *
     * @param jsonNode Node {@link JsonNode}
     * @param key      数据节点对应的 Key 值
     * @return 值
     */
    protected long getLongValue(JsonNode jsonNode, String key) {
        return JsonNodeUtils.findLongValue(jsonNode, key);
    }

    /**
     * 检测 {@link JsonNode} 中是否包含指定 Key
     *
     * @param jsonNode Node {@link JsonNode}
     * @param key      数据节点对应的 Key 值
     * @return {@code true} 包含，{@code false} 未包含
     */
    protected boolean containsKey(JsonNode jsonNode, String key) {
        return JsonNodeUtils.containsKey(jsonNode, key);
    }

    /**
     * 验证响应是否正确。验证数据中是否包含 error 属性，如果包含，则从中读取 error_description 的值，并抛出异常
     * <p>
     * 将包含 error 属性和 error_description 属性的错误响应，认为是标准的错误响应
     *
     * @param jsonNode 响应数据节点 {@link JsonNode}
     */
    protected void validateResponse(JsonNode jsonNode) {
        if (containsKey(jsonNode, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(jsonNode, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
    }

    /**
     * 获取标准的 OAuth2 协议授权码模式请求参数 Map。
     *
     * @param authCallback 认证回调 {@link AuthCallback}
     * @return 请求参数 Map
     */
    protected Map<String, String> authorizationCodeRequestParams(AuthCallback authCallback) {
        Map<String, String> params = new HashMap<>();
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri());
        return params;
    }

    /**
     * 统一的登录入口。当通过{@link AuthDefaultRequest#authorize(String)}授权成功后，会跳转到调用方的相关回调方法中
     * 方法的入参可以使用{@code AuthCallback}，{@code AuthCallback}类中封装好了OAuth2授权回调所需要的参数
     *
     * @param authCallback 用于接收回调参数的实体
     * @return AuthResponse
     */
    @Override
    public AuthResponse<AuthUser> login(AuthCallback authCallback) {
        try {
            checkCode(authCallback);
            if (!config.isIgnoreCheckState()) {
                AuthChecker.checkState(authCallback.getState(), source, authStateCache);
            }

            AuthToken authToken = this.getAccessToken(authCallback);
            AuthUser user = this.getUserInfo(authToken);
            return AuthResponse.<AuthUser>builder().code(AuthResponseStatus.SUCCESS.getCode()).data(user).build();
        } catch (Exception e) {
            Log.error("Failed to login with oauth authorization.", e);
            return this.responseError(e);
        }
    }

    protected void checkCode(AuthCallback authCallback) {
        AuthChecker.checkCode(source, authCallback);
    }


    /**
     * 处理{@link AuthDefaultRequest#login(AuthCallback)} 发生异常的情况，统一响应参数
     *
     * @param e 具体的异常
     * @return AuthResponse
     */
    AuthResponse<AuthUser> responseError(Exception e) {
        int errorCode = AuthResponseStatus.FAILURE.getCode();
        String errorMsg = e.getMessage();
        if (e instanceof AuthException) {
            AuthException authException = ((AuthException) e);
            errorCode = authException.getErrorCode();
            if (StringUtils.isNotEmpty(authException.getErrorMsg())) {
                errorMsg = authException.getErrorMsg();
            }
        }
        return AuthResponse.<AuthUser>builder().code(errorCode).msg(errorMsg).build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权码
     * @return 返回获取accessToken的url
     */
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param refreshToken refreshToken
     * @return 返回获取accessToken的url
     */
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken token
     * @return 返回获取userInfo的url
     */
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo()).queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken()).build();
    }

    /**
     * 返回获取revoke authorization的url
     *
     * @param authToken token
     * @return 返回获取revoke authorization的url
     */
    protected String revokeUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.revoke()).queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken()).build();
    }

    /**
     * 获取state，如果为空， 则默认取当前日期的时间戳
     *
     * @param state 原始的state
     * @return 返回不为null的state
     */
    protected String getRealState(String state) {
        if (StringUtils.isEmpty(state)) {
            state = UuidUtils.getUUID();
        }
        // 缓存state
        authStateCache.cache(state, state);
        return state;
    }

    /**
     * 通用的 authorizationCode 协议
     *
     * @param code code码
     * @return Response
     */
    protected String doPostAuthorizationCode(String code) {
        return UnifiedHttpClient.getAdapter().post(accessTokenUrl(code)).getBody();
    }

    /**
     * 通用的 authorizationCode 协议
     *
     * @param code code码
     * @return Response
     */
    protected String doGetAuthorizationCode(String code) {
        return UnifiedHttpClient.getAdapter().get(accessTokenUrl(code)).getBody();
    }

    /**
     * 通用的 用户信息
     *
     * @param authToken token封装
     * @return Response
     */
    @Deprecated
    protected String doPostUserInfo(AuthToken authToken) {
        return UnifiedHttpClient.getAdapter().post(userInfoUrl(authToken)).getBody();
    }

    /**
     * 通用的 用户信息
     *
     * @param authToken token封装
     * @return Response
     */
    protected String doGetUserInfo(AuthToken authToken) {
        return UnifiedHttpClient.getAdapter().get(userInfoUrl(authToken)).getBody();
    }

    /**
     * 通用的post形式的取消授权方法
     *
     * @param authToken token封装
     * @return Response
     */
    @Deprecated
    protected String doPostRevoke(AuthToken authToken) {
        return UnifiedHttpClient.getAdapter().post(revokeUrl(authToken)).getBody();
    }

    /**
     * 通用的post形式的取消授权方法
     *
     * @param authToken token封装
     * @return Response
     */
    protected String doGetRevoke(AuthToken authToken) {
        return UnifiedHttpClient.getAdapter().get(revokeUrl(authToken)).getBody();
    }

    /**
     * 获取以 {@code separator}分割过后的 scope 信息
     *
     * @param separator     多个 {@code scope} 间的分隔符
     * @param encode        是否 encode 编码
     * @param defaultScopes 默认的 scope， 当客户端没有配置 {@code scopes} 时启用
     * @return String
     * @since 1.16.7
     */
    protected String getScopes(String separator, boolean encode, List<String> defaultScopes) {
        List<String> scopes = config.getScopes();
        if (null == scopes || scopes.isEmpty()) {
            if (null == defaultScopes || defaultScopes.isEmpty()) {
                return "";
            }
            scopes = defaultScopes;
        }
        if (null == separator) {
            // 默认为空格
            separator = " ";
        }
        String scopeStr = String.join(separator, scopes);
        return encode ? HttpUrlEncoding.encode(scopeStr) : scopeStr;
    }

    protected void checkConfig(AuthConfig config) {
        AuthChecker.checkConfig(config, source);
    }
}
