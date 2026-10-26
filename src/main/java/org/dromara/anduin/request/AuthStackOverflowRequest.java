package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthStackoverflowScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpConstants;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.MapUtil;
import tools.jackson.databind.JsonNode;

import java.util.Map;

import static org.dromara.anduin.config.AuthDefaultSource.STACK_OVERFLOW;

/**
 * Stack Overflow登录
 *
 * @author hongwei.peng (pengisgood(at)gmail(dot)com)
 * @since 1.9.0
 */
public class AuthStackOverflowRequest extends AuthDefaultRequest {

    public AuthStackOverflowRequest(AuthConfig config) {
        super(config, STACK_OVERFLOW);
    }

    public AuthStackOverflowRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, STACK_OVERFLOW, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String accessTokenUrl = accessTokenUrl(authCallback.getCode());

        Map<String, String> form = MapUtil.parseStringToMap(accessTokenUrl, false);

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpConstants.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

        String response = UnifiedHttpClient.getAdapter().post(accessTokenUrl, form, httpHeader, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, "expires"))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfoUrl = UrlBuilder.fromBaseUrl(this.source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("site", "stackoverflow")
                .queryParam("key", this.config.getStackOverflowKey())
                .build();
        String response = UnifiedHttpClient.getAdapter().get(userInfoUrl).getBody();
        JsonNode object = toNode(response);
        this.checkResponse(object);

        JsonNode items = getArrayNode(object, "items");
        JsonNode userInfoObject = items.asArray().get(0);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.USER_ID))
                .avatar(getStringValue(userInfoObject, "profile_image"))
                .location(getStringValue(userInfoObject, Keys.USERINFO.LOCATION))
                .nickname(getStringValue(userInfoObject, "display_name"))
                .blog(getStringValue(userInfoObject, "website_url"))
                .gender(AuthUserGender.UNKNOWN)
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
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthStackoverflowScope.values())))
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
