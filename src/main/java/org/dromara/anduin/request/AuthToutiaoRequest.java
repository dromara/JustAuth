package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthToutiaoErrorCode;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import tools.jackson.databind.JsonNode;

/**
 * 今日头条登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.6.0-beta
 */
public class AuthToutiaoRequest extends AuthDefaultRequest {

    public AuthToutiaoRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TOUTIAO);
    }

    public AuthToutiaoRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TOUTIAO, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doGetAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .openId(getStringValue(accessTokenObject, Keys.OAUTH2.OPEN_ID))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userResponse = doGetUserInfo(authToken);

        JsonNode userProfile = toNode(userResponse);

        this.checkResponse(userProfile);

        JsonNode userInfoObject = getDataNode(userProfile);

        boolean isAnonymousUser = getIntValue(userInfoObject, "uid_type") == 14;
        String anonymousUserName = "匿名用户";

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.UID))
                .username(isAnonymousUser ? anonymousUserName : getStringValue(userInfoObject, Keys.USERINFO.SCREENNAME))
                .nickname(isAnonymousUser ? anonymousUserName : getStringValue(userInfoObject, Keys.USERINFO.SCREENNAME))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR_URL))
                .remark(getStringValue(userInfoObject, Keys.USERINFO.DESCRIPTION))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.USERINFO.GENDER)))
                .token(authToken)
                .source(source.toString())
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
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam("auth_only", 1)
                .queryParam("display", 0)
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权码
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE)
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
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR_CODE)) {
            throw new AuthException(AuthToutiaoErrorCode.getErrorCode(getIntValue(object, Keys.RESPONSE_FIELDS.ERROR_CODE)).getDesc());
        }
    }
}
