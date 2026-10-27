package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.GlobalAuthUtils;
import tools.jackson.databind.JsonNode;

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

    private static final String DEVICE_ID = "device_id";

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

        Map<String, String> params = authorizationCodeRequestParams(authCallback);
        params.put(DEVICE_ID, config.getDeviceId());

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, true).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .uid(getStringValue(accessTokenObject, Keys.USERINFO.UID))
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
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .queryParam("client_os_type", "3")
                .queryParam(DEVICE_ID, config.getDeviceId())
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
        params.put(Keys.OAUTH2.APP_KEY, config.getClientId());
        params.put("client_os_type", Optional.ofNullable(config.getClientOsType()).orElse(3).toString());
        params.put(DEVICE_ID, config.getDeviceId());
        params.put("pack_id", config.getPackId());
        params.put(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken());
        params.put("sig", GlobalAuthUtils.generateXmlySignature(params, config.getClientSecret()));

        String rawUserInfo = UnifiedHttpClient.getAdapter().get(source.userInfo(), params, false).getBody();

        JsonNode userInfoObject = toNode(rawUserInfo);
        checkResponse(userInfoObject);

        return AuthUser.builder()
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR_URL))
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
        if (containsKey(jsonNode, Keys.RESPONSE_FIELDS.ERRCODE)) {
            throw new AuthException(getIntValue(jsonNode, Keys.RESPONSE_FIELDS.ERR_NO), getStringValue(jsonNode, Keys.RESPONSE_FIELDS.ERR_DESC));
        }
    }
}
