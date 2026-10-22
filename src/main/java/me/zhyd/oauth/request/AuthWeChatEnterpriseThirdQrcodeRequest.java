package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.log.Log;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthChecker;
import me.zhyd.oauth.utils.JsonUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * 企业微信第三方二维码登录
 * </p>
 *
 * @author zhengjx
 * @since 1.16.3
 */
public class AuthWeChatEnterpriseThirdQrcodeRequest extends AbstractAuthWeChatEnterpriseRequest {
    public AuthWeChatEnterpriseThirdQrcodeRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_QRCODE_THIRD);
    }

    public AuthWeChatEnterpriseThirdQrcodeRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_QRCODE_THIRD, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
                .queryParam("usertype", config.getUsertype())
                .build();
    }

    @Override
    public AuthResponse<AuthUser> login(AuthCallback authCallback) {
        try {
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

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        try {
            String response = doGetAuthorizationCode(accessTokenUrl());
            JsonNode object = this.checkResponse(response);
            return AuthToken.builder()
                    .accessToken(getStringValue(object, "provider_access_token"))
                    .expireIn(getIntValue(object, Keys.OAUTH2__EXPIRES_IN))
                    .code(authCallback.getCode())
                    .build();
        } catch (Exception e) {
            throw new AuthException("企业微信获取token失败", e);
        }
    }

    @Override
    protected String doGetAuthorizationCode(String code) {
        Map<String, Object> params = new HashMap<>();
        params.put("corpid", config.getClientId());
        params.put("provider_secret", config.getClientSecret());
        return UnifiedHttpClient.getAdapter().post(accessTokenUrl(code), JsonUtils.toJson(params)).getBody();
    }

    /**
     * 获取token的URL
     *
     * @return accessTokenUrl
     */
    protected String accessTokenUrl() {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        JsonNode response = this.checkResponse(doGetUserInfo(authToken));
        return AuthUser.builder()
                .rawUserInfo(response)
                .build();
    }

    @Override
    protected String doGetUserInfo(AuthToken authToken) {
        Map<String, Object> params = new HashMap<>();
        params.put("auth_code", authToken.getCode());

        return UnifiedHttpClient.getAdapter().post(userInfoUrl(authToken), JsonUtils.toJson(params)).getBody();
    }

    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken()).
                build();
    }

    private JsonNode checkResponse(String response) {
        JsonNode object = toNode(response);
        if (containsKey(object, Keys.VARIANT__ERRCODE) && getIntValue(object, Keys.VARIANT__ERRCODE) != 0) {
            throw new AuthException(getStringValue(object, Keys.VARIANT__ERRMSG), source);
        }
        return object;
    }
}
