package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthLinkedinScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.TokenUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import tools.jackson.databind.JsonNode;


/**
 * 领英登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.4.0
 */
public class AuthLinkedinRequest extends AuthDefaultRequest {

    public AuthLinkedinRequest(AuthConfig config) {
        super(config, AuthDefaultSource.LINKEDIN);
    }

    public AuthLinkedinRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.LINKEDIN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return this.getToken(accessTokenUrl(authCallback.getCode()));
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.HOST, "api.linkedin.com");
        httpHeader.add(HttpHeaders.CONNECTION, "Keep-Alive");
        httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(accessToken));

        String response = UnifiedHttpClient.getAdapter().get(userInfoUrl(authToken), null, httpHeader, false).getBody();

        JsonNode userInfoObject = toNode(response);

        this.checkResponse(userInfoObject);

        String userName = getUserName(userInfoObject);
        // 获取用户头像
        String avatar = this.getAvatar(userInfoObject);
        // 获取用户邮箱地址
        String email = this.getUserEmail(accessToken);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.ID))
                .username(userName)
                .nickname(userName)
                .avatar(avatar)
                .email(email)
                .token(authToken)
                .gender(AuthUserGender.UNKNOWN)
                .source(source.toString())
                .build();
    }

    /**
     * 获取用户的真实名
     *
     * @param userInfoObject 用户json对象
     * @return 用户名
     */
    private String getUserName(JsonNode userInfoObject) {
        String firstName;
        String lastName;
        // 获取firstName
        if (containsKey(userInfoObject, "localizedFirstName")) {
            firstName = getStringValue(userInfoObject, "localizedFirstName");
        } else {
            firstName = getStringValue(userInfoObject, "firstName");
        }
        // 获取lastName
        if (containsKey(userInfoObject, "localizedLastName")) {
            lastName = getStringValue(userInfoObject, "localizedLastName");
        } else {
            lastName = getUserName(userInfoObject, "lastName");
        }
        return firstName + " " + lastName;
    }

    /**
     * 获取用户的头像
     *
     * @param userInfoObject 用户json对象
     * @return 用户的头像地址
     */
    private String getAvatar(JsonNode userInfoObject) {
        JsonNode profilePictureObject = getObjectNode(userInfoObject, "profilePicture");
        if (null == profilePictureObject || !containsKey(profilePictureObject, "displayImage~")) {
            return null;
        }
        JsonNode displayImageObject = getObjectNode(profilePictureObject, "displayImage~");
        if (null == displayImageObject || !containsKey(displayImageObject, "elements")) {
            return null;
        }
        JsonNode displayImageElements = getArrayNode(displayImageObject, "elements");
        if (null == displayImageElements || displayImageElements.isEmpty()) {
            return null;
        }
        JsonNode largestImageObj = displayImageElements.asArray().get(displayImageElements.size() - 1);
        if (null == largestImageObj || !containsKey(largestImageObj, "identifiers")) {
            return null;
        }
        JsonNode identifiers = getArrayNode(largestImageObj, "identifiers");
        if (null == identifiers || identifiers.isEmpty()) {
            return null;
        }
        return getStringValue(identifiers.asArray().get(0), "identifier");
    }

    /**
     * 获取用户的email
     *
     * @param accessToken 用户授权后返回的token
     * @return 用户的邮箱地址
     */
    private String getUserEmail(String accessToken) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.HOST, "api.linkedin.com");
        httpHeader.add("Connection", "Keep-Alive");
        httpHeader.add("Authorization", "Bearer " + accessToken);

        String emailResponse = UnifiedHttpClient.getAdapter().get("https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))", null, httpHeader, false)
                .getBody();
        JsonNode emailObj = toNode(emailResponse);

        this.checkResponse(emailObj);

        JsonNode elements = getArrayNode(emailObj, "elements");
        if (elements == null || elements.isEmpty()) {
            return null;
        }

        JsonNode element = elements.get(0);

        JsonNode handle = element == null ? null : getObjectNode(element, "handle~");
        return null == handle ? null : getStringValue(handle, "emailAddress");
    }

    private String getUserName(JsonNode userInfoObject, String nameKey) {
        String firstName;
        JsonNode firstNameObj = getObjectNode(userInfoObject, nameKey);
        JsonNode localizedObj = getObjectNode(firstNameObj, "localized");
        JsonNode preferredLocaleObj = getObjectNode(firstNameObj, "preferredLocale");
        firstName = getStringValue(localizedObj, getStringValue(preferredLocaleObj, "language") + "_" + getStringValue(preferredLocaleObj, "country"));
        return firstName;
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.ERROR_DESCRIPTION), source);
        }
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.HOST, "www.linkedin.com");
        httpHeader.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

        String response = UnifiedHttpClient.getAdapter().post(accessTokenUrl, null, httpHeader).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2__REFRESH_TOKEN))
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
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthLinkedinScope.values())))
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
                .queryParam("projection", "(id,firstName,lastName,profilePicture(displayImage~:playableStreams))")
                .build();
    }
}
