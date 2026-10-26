package org.dromara.anduin.request;

import org.apache.commons.lang3.StringUtils;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthBaiduScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

/**
 * 百度账号登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthBaiduRequest extends AuthDefaultRequest {

    public AuthBaiduRequest(AuthConfig config) {
        super(config, AuthDefaultSource.BAIDU);
    }

    public AuthBaiduRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.BAIDU, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        return getAuthToken(response);
    }

    /**
     * <a href="https://openapi.baidu.com/rest/2.0/passport/users/getInfo?access_token=121.c86e87cc0828cc1dabb8faee540531d4.YsUIAWvYbgqVni1VhkgKgyLh8nEyELbDOEZs_OA.OgDgmA">...</a>
     * <a href="https://openapi.baidu.com/rest/2.0/passport/users/getInfo?access_token=121.2907d9facf9fb97adf7287fa75496eda.Y3NSjR3-3HKt1RgT0HEl7GgxRXT5gOOVdngXezY.OcC_7g">...</a>
     * 新旧应用返回的用户信息不一致
     *
     * @param authToken token信息
     * @return AuthUser
     */
    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);

        JsonNode userInfoObject = toNode(userInfo);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(containsKey(userInfoObject, Keys.USERINFO.USERID) ? getStringValue(userInfoObject, Keys.USERINFO.USERID) : getStringValue(userInfoObject, Keys.OAUTH2.SCOPES.OPENID))
                .username(getStringValue(userInfoObject, Keys.USERINFO.USERNAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.USERNAME))
                .avatar(getAvatar(userInfoObject))
                .remark(getStringValue(userInfoObject, "userdetail"))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.USERINFO.SEX)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    private String getAvatar(JsonNode object) {
        String protrait = getStringValue(object, "portrait");
        return StringUtils.isEmpty(protrait) ? null : String.format("http://himg.bdimg.com/sys/portrait/item/%s.jpg", protrait);
    }

    @Override
    public AuthResponse<?> revoke(AuthToken authToken) {
        String response = doGetRevoke(authToken);

        JsonNode object = toNode(response);
        this.checkResponse(object);
        // 返回1表示取消授权成功，否则失败
        AuthResponseStatus status = getIntValue(object, Keys.RESPONSE_FIELDS.RESULT) == 1 ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        String refreshUrl = UrlBuilder.fromBaseUrl(this.source.refresh())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN)
                .queryParam(Keys.OAUTH2.REFRESH_TOKEN, authToken.getRefreshToken())
                .queryParam(Keys.OAUTH2.CLIENT_ID, this.config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, this.config.getClientSecret())
                .build();

        String response = UnifiedHttpClient.getAdapter().get(refreshUrl).getBody();

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(this.getAuthToken(response))
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
                .queryParam("display", "popup")
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthBaiduScope.values())))
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR) || containsKey(object, Keys.RESPONSE_FIELDS.ERROR_CODE)) {
            String msg = containsKey(object, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION) ? getStringValue(object, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION) : getStringValue(object, "error_msg");
            throw new AuthException(msg);
        }
    }

    private AuthToken getAuthToken(String response) {

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .build();
    }
}
