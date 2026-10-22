package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthBaiduScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import org.apache.commons.lang3.StringUtils;
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
     * https://openapi.baidu.com/rest/2.0/passport/users/getInfo?access_token=121.c86e87cc0828cc1dabb8faee540531d4.YsUIAWvYbgqVni1VhkgKgyLh8nEyELbDOEZs_OA.OgDgmA
     * https://openapi.baidu.com/rest/2.0/passport/users/getInfo?access_token=121.2907d9facf9fb97adf7287fa75496eda.Y3NSjR3-3HKt1RgT0HEl7GgxRXT5gOOVdngXezY.OcC_7g
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
                .uuid(containsKey(userInfoObject, Keys.USERID) ? getStringValue(userInfoObject, Keys.USERID) : getStringValue(userInfoObject, Keys.OAUTH2_SCOPE__OPENID))
                .username(getStringValue(userInfoObject, Keys.USERNAME))
                .nickname(getStringValue(userInfoObject, Keys.USERNAME))
                .avatar(getAvatar(userInfoObject))
                .remark(getStringValue(userInfoObject, "userdetail"))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, "sex")))
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
        AuthResponseStatus status = getIntValue(object, Keys.RESULT) == 1 ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        String refreshUrl = UrlBuilder.fromBaseUrl(this.source.refresh())
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2__REFRESH_TOKEN)
                .queryParam(Keys.OAUTH2__REFRESH_TOKEN, authToken.getRefreshToken())
                .queryParam(Keys.OAUTH2__CLIENT_ID, this.config.getClientId())
                .queryParam(Keys.OAUTH2__CLIENT_SECRET, this.config.getClientSecret())
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
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthBaiduScope.values())))
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR) || containsKey(object, Keys.ERROR_CODE)) {
            String msg = containsKey(object, Keys.ERROR_DESCRIPTION) ? getStringValue(object, Keys.ERROR_DESCRIPTION) : getStringValue(object, "error_msg");
            throw new AuthException(msg);
        }
    }

    private AuthToken getAuthToken(String response) {
        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);
        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2__SCOPE))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .build();
    }
}
