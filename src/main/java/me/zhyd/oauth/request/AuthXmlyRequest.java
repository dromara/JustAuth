package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * 喜马拉雅登录
 *
 * @author zwzch (zwzch4j@gmail.com)
 * @since 1.15.9
 */
public class AuthXmlyRequest extends AuthDefaultRequest {

    public AuthXmlyRequest(AuthConfig config) {
        super(config, AuthDefaultSource.XMLY);
    }

    public AuthXmlyRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.XMLY, authStateCache);
    }

    /**
     * 获取access token
     *
     * @param authCallback 授权成功后的回调参数
     * @return token
     * @see AuthDefaultRequest#authorize(String)
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> params = new HashMap<>(9);
        params.put(Keys.OAUTH2__CODE, authCallback.getCode());
        params.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret());
        params.put("device_id", config.getDeviceId());
        params.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri());
        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, true).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .uid(getStringValue(accessTokenObject, Keys.UID))
                .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.15.8
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
                .queryParam("client_os_type", "3")
                .queryParam("device_id", config.getDeviceId())
                .build();
    }

    /**
     * 使用token换取用户信息
     *
     * @param authToken token信息
     * @return 用户信息
     * @see AuthDefaultRequest#getAccessToken(AuthCallback)
     */
    @Override
    public AuthUser getUserInfo(AuthToken authToken) {

        Map<String, String> params = new TreeMap<>();
        params.put(Keys.VARIANT__APP_KEY, config.getClientId());
        params.put("client_os_type", Optional.ofNullable(config.getClientOsType()).orElse(3).toString());
        params.put("device_id", config.getDeviceId());
        params.put("pack_id", config.getPackId());
        params.put(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken());
        params.put("sig", GlobalAuthUtils.generateXmlySignature(params, config.getClientSecret()));
        String rawUserInfo = UnifiedHttpClient.getAdapter().get(source.userInfo(), params, false).getBody();

        JsonNode userInfoObject = toNode(rawUserInfo);
        checkResponse(userInfoObject);

        return AuthUser.builder()
                .uuid(getStringValue(userInfoObject, Keys.ID))
                .nickname(getStringValue(userInfoObject, Keys.NICKNAME))
                .avatar(getStringValue(userInfoObject, Keys.AVATAR_URL))
                .rawUserInfo(userInfoObject)
                .source(source.toString())
                .token(authToken)
                .gender(AuthUserGender.UNKNOWN)
                .build();
    }

    /**
     * 校验响应结果
     *
     * @param jsonNode 接口返回的结果
     */
    private void checkResponse(JsonNode jsonNode) {
        if (containsKey(jsonNode, Keys.VARIANT__ERRCODE)) {
            throw new AuthException(getIntValue(jsonNode, "error_no"), getStringValue(jsonNode, "error_desc"));
        }
    }
}
