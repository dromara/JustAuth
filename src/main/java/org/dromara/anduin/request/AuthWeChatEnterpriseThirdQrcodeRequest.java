package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.log.Log;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthChecker;
import org.dromara.anduin.utils.JsonUtils;
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
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
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
        String response = doGetAuthorizationCode(accessTokenUrl());

        JsonNode object = this.checkResponse(response);

        return AuthToken.builder()
                .accessToken(getStringValue(object, "provider_access_token"))
                .expireIn(getIntValue(object, Keys.OAUTH2.EXPIRES_IN))
                .code(authCallback.getCode())
                .build();
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
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken()).
                build();
    }

    private JsonNode checkResponse(String response) {
        JsonNode object = toNode(response);
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERRCODE) && getIntValue(object, Keys.RESPONSE_FIELDS.ERRCODE) != 0) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERRMSG), source);
        }
        return object;
    }
}
