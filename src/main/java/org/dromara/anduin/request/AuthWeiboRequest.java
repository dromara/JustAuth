package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthWeiboScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.IpUtils;
import org.dromara.anduin.utils.TokenUtils;
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
        validateResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .uid(getStringValue(accessTokenObject, Keys.USERINFO.UID))
                .openId(getStringValue(accessTokenObject, Keys.USERINFO.UID))
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
        if (containsKey(userInfoObject, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(userInfoObject, Keys.RESPONSE_FIELDS.ERROR));
        }
        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .avatar(getStringValue(userInfoObject, "profile_image_url"))
                .blog(containsKey(userInfoObject, Keys.USERINFO.URL) ? "https://weibo.com/" + getStringValue(userInfoObject, "profile_url") : getStringValue(userInfoObject
                        , Keys.USERINFO.URL))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.SCREENNAME))
                .location(getStringValue(userInfoObject, Keys.USERINFO.LOCATION))
                .remark(getStringValue(userInfoObject, Keys.USERINFO.DESCRIPTION))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.USERINFO.GENDER)))
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
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.USERINFO.UID, authToken.getUid())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthWeiboScope.values())))
                .build();
    }

    @Override
    public AuthResponse<?> revoke(AuthToken authToken) {
        String response = doGetRevoke(authToken);

        JsonNode object = toNode(response);
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            return AuthResponse.builder()
                    .code(AuthResponseStatus.FAILURE.getCode())
                    .msg(getStringValue(object, Keys.RESPONSE_FIELDS.ERROR))
                    .build();
        }
        // 返回 result = true 表示取消授权成功，否则失败
        AuthResponseStatus status = getBooleanValue(object, Keys.RESPONSE_FIELDS.RESULT) ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }
}
