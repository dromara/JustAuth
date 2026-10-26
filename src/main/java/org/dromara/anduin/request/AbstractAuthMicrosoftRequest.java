package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthMicrosoftScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.MapUtil;

import org.apache.commons.lang3.StringUtils;
import tools.jackson.databind.JsonNode;

import java.util.Map;

/**
 * 微软登录抽象类,负责处理使用微软国际和微软中国账号登录第三方网站的登录方式
 *
 * @author mroldx (xzfqq5201314@gmail.com)
 * @since 1.16.4
 */
public abstract class AbstractAuthMicrosoftRequest extends AuthDefaultRequest {

    protected AbstractAuthMicrosoftRequest(AuthConfig config, AuthSource source) {
        super(config, source);
    }


    protected AbstractAuthMicrosoftRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        super(config, source, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return getToken(accessTokenUrl(authCallback.getCode()));
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl) {
        HttpHeader httpHeader = new HttpHeader();

        Map<String, String> form = MapUtil.parseStringToMap(accessTokenUrl, false);

        String response = UnifiedHttpClient.getAdapter().post(accessTokenUrl, form, httpHeader, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String token = authToken.getAccessToken();
        String tokenType = authToken.getTokenType();
        String jwt = tokenType + " " + token;

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.AUTHORIZATION, jwt);

        String response = UnifiedHttpClient.getAdapter().get(userInfoUrl(authToken), null, httpHeader, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .username(getStringValue(userInfoObject, "userPrincipalName"))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.DISPLAY_NAME))
                .location(getStringValue(userInfoObject, "officeLocation"))
                .email(getStringValue(userInfoObject, "mail"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 刷新access token （续期）
     *
     * @param authToken 登录成功后返回的Token信息
     * @return AuthResponse
     */
    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(refreshTokenUrl(authToken.getRefreshToken())))
                .build();
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
        // 兼容 Microsoft Entra ID 登录（原微软 AAD）
        // @since 1.16.6
        String tenantId = StringUtils.isEmpty(config.getTenantId()) ? "common" : config.getTenantId();
        return UrlBuilder.fromBaseUrl(String.format(source.authorize(), tenantId))
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .queryParam("response_mode", "query")
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthMicrosoftScope.values())))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权code
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code) {
        String tenantId = StringUtils.isEmpty(config.getTenantId()) ? "common" : config.getTenantId();
        return UrlBuilder.fromBaseUrl(String.format(source.accessToken(), tenantId))
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthMicrosoftScope.values())))
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户授权后的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo()).build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param refreshToken 用户授权后的token
     * @return 返回获取accessToken的url
     */
    @Override
    protected String refreshTokenUrl(String refreshToken) {
        String tenantId = StringUtils.isEmpty(config.getTenantId()) ? "common" : config.getTenantId();
        return UrlBuilder.fromBaseUrl(String.format(source.refresh(), tenantId))
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthMicrosoftScope.values())))
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .build();
    }
}
