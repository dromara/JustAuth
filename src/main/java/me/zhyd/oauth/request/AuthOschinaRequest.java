package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import tools.jackson.databind.JsonNode;

/**
 * oschina登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthOschinaRequest extends AuthDefaultRequest {

    public AuthOschinaRequest(AuthConfig config) {
        super(config, AuthDefaultSource.OSCHINA);
    }

    public AuthOschinaRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.OSCHINA, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .uid(getStringValue(accessTokenObject, Keys.USERINFO.UID))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR))
                .blog(getStringValue(userInfoObject, Keys.USERINFO.URL))
                .location(getStringValue(userInfoObject, Keys.USERINFO.LOCATION))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.USERINFO.GENDER)))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权回调时带回的授权码
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam("dataType", "json")
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户授权后的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("dataType", "json")
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
    }
}
