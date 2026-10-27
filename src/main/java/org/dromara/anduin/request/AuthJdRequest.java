package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthJdScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.GlobalAuthUtils;
import tools.jackson.databind.JsonNode;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * 京东登录
 *
 * @author harry.lee (harryleexyz@qq.com)
 * @since 1.15.0
 */
public class AuthJdRequest extends AuthDefaultRequest {

    public AuthJdRequest(AuthConfig config) {
        super(config, AuthDefaultSource.JD);
    }

    public AuthJdRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.JD, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.APP_KEY, config.getClientId());
        params.put("app_secret", config.getClientSecret());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        JsonNode accessTokenObject = toNode(response);

        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .openId(getStringValue(accessTokenObject, Keys.OAUTH2.OPEN_ID))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        UrlBuilder urlBuilder = UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2.APP_KEY, config.getClientId())
                .queryParam("method", "jingdong.user.getUserInfoByOpenId")
                .queryParam("360buy_param_json", "{\"openId\":\"" + authToken.getOpenId() + "\"}")
                .queryParam("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                .queryParam("v", "2.0");
        urlBuilder.queryParam("sign", GlobalAuthUtils.generateJdSignature(config.getClientSecret(), urlBuilder.getReadOnlyParams()));

        String response = UnifiedHttpClient.getAdapter().post(urlBuilder.build(true)).getBody();

        JsonNode responseObject = toNode(response);
        this.checkResponse(responseObject);

        JsonNode userInfoObject = this.getUserDataJsonObject(responseObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(authToken.getOpenId())
                .username(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .avatar(getStringValue(userInfoObject, "imageUrl"))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, "gendar")))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 个人用户无法申请应用
     * 暂时只能参考官网给出的返回结果解析
     *
     * @param object 请求返回结果
     * @return data JSONObject
     */
    private JsonNode getUserDataJsonObject(JsonNode object) {
        JsonNode response = getObjectNode(object, "jingdong_user_getUserInfoByOpenId_response");
        JsonNode result = getObjectNode(response, "getuserinfobyappidandopenid_result");
        return getDataNode(result);
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.APP_KEY, config.getClientId());
        params.put("app_secret", config.getClientSecret());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);
        params.put(Keys.OAUTH2.REFRESH_TOKEN, oldToken.getRefreshToken());
        String response = UnifiedHttpClient.getAdapter().post(source.refresh(), params, false).getBody();

        JsonNode refreshTokenObject = toNode(response);
        this.checkResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(refreshTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                        .expireIn(getIntValue(refreshTokenObject, Keys.OAUTH2.EXPIRES_IN))
                        .refreshToken(getStringValue(refreshTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                        .scope(getStringValue(refreshTokenObject, Keys.OAUTH2.SCOPE))
                        .openId(getStringValue(refreshTokenObject, Keys.OAUTH2.OPEN_ID))
                        .build())
                .build();
    }

    private void checkResponse(JsonNode object) {
        if (containsKey(object, "error_response")) {
            JsonNode errorResponse = object.get("error_response");
            throw new AuthException(getStringValue(errorResponse, "zh_desc"));
        }
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.APP_KEY, config.getClientId())
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthJdScope.values())))
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }

}
