package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.UrlBuilder;
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
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .uid(getStringValue(accessTokenObject, Keys.UID))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);
        JsonNode object = toNode(response);
        this.checkResponse(object);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(getStringValue(object, Keys.ID))
                .username(getStringValue(object, Keys.NAME))
                .nickname(getStringValue(object, Keys.NAME))
                .avatar(getStringValue(object, Keys.AVATAR))
                .blog(getStringValue(object, Keys.URL))
                .location(getStringValue(object, Keys.LOCATION))
                .gender(AuthUserGender.getRealGender(getStringValue(object, Keys.GENDER)))
                .email(getStringValue(object, Keys.OAUTH2_SCOPE__EMAIL))
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
                .queryParam(Keys.OAUTH2__CODE, code)
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
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
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("dataType", "json")
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.ERROR_DESCRIPTION));
        }
    }
}
