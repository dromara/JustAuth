package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthCodingScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.JsonNodeUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.databind.JsonNode;

/**
 * Coding登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthCodingRequest extends AuthDefaultRequest {

    public AuthCodingRequest(AuthConfig config) {
        super(config, AuthDefaultSource.CODING);
    }

    public AuthCodingRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.CODING, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doGetAuthorizationCode(authCallback.getCode());
        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);
        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);
        JsonNode object = toNode(response);
        this.checkResponse(object);

        object = JsonNodeUtils.findObjectNode(object, Keys.DATA);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(getStringValue(object, Keys.ID))
                .username(getStringValue(object, Keys.NAME))
                .avatar("https://coding.net" + getStringValue(object, Keys.AVATAR))
                .blog("https://coding.net" + getStringValue(object, "path"))
                .nickname(getStringValue(object, Keys.NAME))
                .company(getStringValue(object, Keys.COMPANY))
                .location(getStringValue(object, Keys.LOCATION))
                .gender(AuthUserGender.getRealGender(getStringValue(object, "sex")))
                .email(getStringValue(object, Keys.OAUTH2_SCOPE__EMAIL))
                .remark(getStringValue(object, "slogan"))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (getIntValue(object, Keys.OAUTH2__CODE) != 0) {
            throw new AuthException(getStringValue(object, "msg"));
        }
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
        return UrlBuilder.fromBaseUrl(String.format(source.authorize(), config.getDomainPrefix()))
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthCodingScope.values())))
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权码
     * @return 返回获取accessToken的url
     */
    @Override
    public String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(String.format(source.accessToken(), config.getDomainPrefix()))
                .queryParam(Keys.OAUTH2__CODE, code)
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken token
     * @return 返回获取userInfo的url
     */
    @Override
    public String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(String.format(source.userInfo(), config.getDomainPrefix()))
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .build();
    }
}
