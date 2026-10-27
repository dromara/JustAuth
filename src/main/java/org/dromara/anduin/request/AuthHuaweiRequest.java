package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthHuaweiScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

import static org.dromara.anduin.enums.AuthResponseStatus.SUCCESS;

/**
 * 华为授权登录
 * <p>
 * 当前方式未来可能被废弃，建议使用 {@link AuthHuaweiV3Request}
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @version 1.0
 * @since 1.10.0
 */
@Deprecated
public class AuthHuaweiRequest extends AuthDefaultRequest {

    public AuthHuaweiRequest(AuthConfig config) {
        super(config, AuthDefaultSource.HUAWEI);
    }

    public AuthHuaweiRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.HUAWEI, authStateCache);
    }

    /**
     * 获取access token
     *
     * @param authCallback 授权成功后的回调参数
     * @return token
     * @see AuthDefaultRequest#authorize()
     * @see AuthDefaultRequest#authorize(String)
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> params = authorizationCodeRequestParams(authCallback);

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        return getAuthToken(response);
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
        Map<String, String> params = new HashMap<>(7);
        params.put("nsp_ts", System.currentTimeMillis() + "");
        params.put(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken());
        params.put("nsp_fmt", "JS");
        params.put(Keys.OAUTH2.OPEN_ID, "OPENID");
        // form.put("nsp_svc", "OpenUP.User.getInfo");
        params.put("nsp_svc", "huawei.oauth2.user.getTokenInfo");

        String response = UnifiedHttpClient.getAdapter().post(source.userInfo(), params, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        AuthUserGender gender = getRealGender(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "userID"))
                .username(getStringValue(userInfoObject, "userName"))
                .nickname(getStringValue(userInfoObject, "userName"))
                .gender(gender)
                .avatar(getStringValue(userInfoObject, "headPictureURL"))
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
        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2.REFRESH_TOKEN, authToken.getRefreshToken());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);

        String response = UnifiedHttpClient.getAdapter().post(source.refresh(), params, false).getBody();

        return AuthResponse.<AuthToken>builder().code(SUCCESS.getCode()).data(getAuthToken(response)).build();
    }

    private AuthToken getAuthToken(String response) {
        JsonNode object = toNode(response);

        this.checkResponse(object);

        return AuthToken.builder()
                .accessToken(getStringValue(object, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(object, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(object, Keys.OAUTH2.REFRESH_TOKEN))
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
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam("access_type", "offline")
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthHuaweiScope.values())))
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam("nsp_ts", System.currentTimeMillis())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("nsp_fmt", "JS")
                .queryParam("nsp_svc", "OpenUP.User.getInfo")
                .build();
    }

    /**
     * 获取用户的实际性别。华为系统中，用户的性别：1表示女，0表示男
     *
     * @param object obj
     * @return AuthUserGender
     */
    private AuthUserGender getRealGender(JsonNode object) {
        int genderCodeInt = getIntValue(object, Keys.USERINFO.GENDER);
        String genderCode = genderCodeInt == 1 ? "0" : (genderCodeInt == 0) ? "1" : genderCodeInt + "";
        return AuthUserGender.getRealGender(genderCode);
    }

    /**
     * 校验响应结果
     *
     * @param object 接口返回的结果
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, "NSP_STATUS")) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERROR));
        }
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(object, "sub_error") + ":" + getStringValue(object, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
    }
}
