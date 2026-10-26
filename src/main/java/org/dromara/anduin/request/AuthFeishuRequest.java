package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.apache.commons.lang3.StringUtils;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
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
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * 飞书平台，企业自建应用授权登录，原逻辑由 beacon 集成于 1.14.0 版，但最新的飞书 api 已修改，并且飞书平台一直为 {@code Deprecated} 状态
 * <p>
 * 所以，最终修改该平台的实际发布版本为 1.15.9
 *
 * @author beacon
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com) 重构业务逻辑 20210101
 * @since 1.15.9
 */
public class AuthFeishuRequest extends AuthDefaultRequest {

    private static final String APP_ACCESS_TOKEN = "app_access_token";

    public AuthFeishuRequest(AuthConfig config) {
        super(config, AuthDefaultSource.FEISHU);
    }

    public AuthFeishuRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.FEISHU, authStateCache);
    }

    /**
     * 获取 app_access_token（企业自建应用）
     * <p>
     * Token 有效期为 2 小时，在此期间调用该接口 token 不会改变。当 token 有效期小于 30 分的时候，再次请求获取 token 的时候，
     * 会生成一个新的 token，与此同时老的 token 依然有效。
     *
     * @return appAccessToken
     */
    private String getAppAccessToken() {
        String cacheKey = this.source.getName().concat(":" + APP_ACCESS_TOKEN + ":").concat(config.getClientId());
        String cacheAppAccessToken = this.authStateCache.get(cacheKey);
        if (StringUtils.isNotEmpty(cacheAppAccessToken)) {
            return cacheAppAccessToken;
        }

        String url = "https://open.feishu.cn/open-apis/auth/v3/" + APP_ACCESS_TOKEN + "/internal/";

        Map<String, Object> params = new HashMap<>();
        params.put(Keys.OAUTH2.APP_ID, config.getClientId());
        params.put("app_secret", config.getClientSecret());

        String response = UnifiedHttpClient.getAdapter().post(url, JsonUtils.toJson(params), new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);
        String appAccessToken = getStringValue(accessTokenObject, APP_ACCESS_TOKEN);
        // 缓存 app access token
        this.authStateCache.cache(cacheKey, appAccessToken);
        return appAccessToken;
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, Object> params = new HashMap<>();
        params.put(APP_ACCESS_TOKEN, this.getAppAccessToken());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        return getToken(params, this.source.accessToken());

    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();
        String response = UnifiedHttpClient.getAdapter().get(source.userInfo(), null, new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(accessToken)), false).getBody();

        JsonNode responseObject = toNode(response);
        this.checkResponse(responseObject);

        JsonNode userInfoObject = getDataNode(responseObject);

        return AuthUser.builder()
                .rawUserInfo(responseObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.UNION_ID))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR_URL))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        Map<String, Object> params = new HashMap<>();
        params.put(APP_ACCESS_TOKEN, this.getAppAccessToken());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);
        params.put(Keys.OAUTH2.REFRESH_TOKEN, authToken.getRefreshToken());

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(params, this.source.refresh()))
                .build();

    }

    private AuthToken getToken(Map<String, Object> param, String url) {
        String response = UnifiedHttpClient.getAdapter().post(url, JsonUtils.toJson(param), new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)).getBody();

        JsonNode responseObject = toNode(response);
        this.checkResponse(responseObject);

        JsonNode accessTokenObject = getDataNode(responseObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .openId(getStringValue(accessTokenObject, Keys.OAUTH2.OPEN_ID))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.APP_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, GlobalAuthUtils.urlEncode(config.getRedirectUri()))
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }


    /**
     * 校验响应内容是否正确
     *
     * @param jsonObject 响应内容
     */
    private void checkResponse(JsonNode jsonObject) {
        if (getIntValue(jsonObject, Keys.OAUTH2.CODE) != 0) {
            throw new AuthException(getStringValue(jsonObject, Keys.USERINFO.MESSAGE));
        }
    }

}
