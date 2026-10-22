package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthWeiboScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.IpUtils;
import me.zhyd.oauth.utils.TokenUtils;
import tools.jackson.databind.JsonNode;


/**
 * 微博登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthWeiboRequest extends AuthDefaultRequest {

    public AuthWeiboRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WEIBO);
    }

    public AuthWeiboRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WEIBO, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        if (containsKey(accessTokenObject, Keys.ERROR)) {
            throw new AuthException(getStringValue(accessTokenObject, Keys.ERROR_DESCRIPTION));
        }

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .uid(getStringValue(accessTokenObject, Keys.UID))
                .openId(getStringValue(accessTokenObject, Keys.UID))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();
        String uid = authToken.getUid();
        String oauthParam = String.format("uid=%s&access_token=%s", uid, accessToken);

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.oauth2(oauthParam));
        httpHeader.add("API-RemoteIP", IpUtils.getLocalIp());
        String userInfo = UnifiedHttpClient.getAdapter().get(userInfoUrl(authToken), null, httpHeader, false).getBody();

        JsonNode userInfoObject = toNode(userInfo);
        if (containsKey(userInfoObject, Keys.ERROR)) {
            throw new AuthException(getStringValue(userInfoObject, Keys.ERROR));
        }
        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.ID))
                .username(getStringValue(userInfoObject, Keys.NAME))
                .avatar(getStringValue(userInfoObject, "profile_image_url"))
                .blog(containsKey(userInfoObject, Keys.URL) ? "https://weibo.com/" + getStringValue(userInfoObject, "profile_url") : getStringValue(userInfoObject
                        , Keys.URL))
                .nickname(getStringValue(userInfoObject, "screen_name"))
                .location(getStringValue(userInfoObject, Keys.LOCATION))
                .remark(getStringValue(userInfoObject, Keys.DESCRIPTION))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.GENDER)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken authToken
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.UID, authToken.getUid())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthWeiboScope.values())))
                .build();
    }

    @Override
    public AuthResponse<?> revoke(AuthToken authToken) {
        String response = doGetRevoke(authToken);

        JsonNode object = toNode(response);
        if (containsKey(object, Keys.ERROR)) {
            return AuthResponse.builder()
                    .code(AuthResponseStatus.FAILURE.getCode())
                    .msg(getStringValue(object, Keys.ERROR))
                    .build();
        }
        // 返回 result = true 表示取消授权成功，否则失败
        AuthResponseStatus status = getBooleanValue(object, Keys.RESULT) ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }
}
