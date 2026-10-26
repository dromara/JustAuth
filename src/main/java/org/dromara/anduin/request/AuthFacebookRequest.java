package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthFacebookScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.GlobalAuthUtils;
import tools.jackson.databind.JsonNode;

/**
 * Facebook登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.3.0
 */
public class AuthFacebookRequest extends AuthDefaultRequest {

    public AuthFacebookRequest(AuthConfig config) {
        super(config, AuthDefaultSource.FACEBOOK);
    }

    public AuthFacebookRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.FACEBOOK, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
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
                .blog(getStringValue(userInfoObject, "link"))
                .avatar(getUserPicture(userInfoObject))
                .location(getStringValue(userInfoObject, "locale"))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .gender(AuthUserGender.getRealGender(getStringValue(userInfoObject, Keys.USERINFO.GENDER)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    private String getUserPicture(JsonNode object) {
        String picture = null;
        if (containsKey(object, Keys.USERINFO.PICTURE)) {
            JsonNode pictureObj = getObjectNode(object, Keys.USERINFO.PICTURE);
            JsonNode dataObject = getDataNode(pictureObj);
            if (null != dataObject) {
                picture = getStringValue(dataObject, Keys.USERINFO.URL);
            }
        }
        return picture;
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("fields", "id,name,birthday,gender,hometown,email,devices,picture.width(400),link")
                .build();
    }

    @Override
    protected void checkConfig(AuthConfig config) {
        super.checkConfig(config);
        // facebook的回调地址必须为https的链接
        if (AuthDefaultSource.FACEBOOK == source && !GlobalAuthUtils.isHttpsProtocol(config.getRedirectUri())) {
            // Facebook's redirect uri must use the HTTPS protocol
            throw new AuthException(AuthResponseStatus.ILLEGAL_REDIRECT_URI, source);
        }
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            JsonNode errorObject = getObjectNode(object, Keys.RESPONSE_FIELDS.ERROR);
            throw new AuthException(getStringValue(errorObject, Keys.USERINFO.MESSAGE));
        }
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthFacebookScope.values())))
                .build();
    }
}
