package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthPinterestScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

import java.util.Objects;

import static org.dromara.anduin.config.AuthDefaultSource.PINTEREST;

/**
 * Pinterest登录
 *
 * @author hongwei.peng (pengisgood(at)gmail(dot)com)
 * @since 1.9.0
 */
public class AuthPinterestRequest extends AuthDefaultRequest {

    private static final String FAILURE = "failure";

    public AuthPinterestRequest(AuthConfig config) {
        super(config, PINTEREST);
    }

    public AuthPinterestRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, PINTEREST, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userinfoUrl = userInfoUrl(authToken);
        // TODO: 是否需要 .setFollowRedirects(true)
        String response = UnifiedHttpClient.getAdapter().get(userinfoUrl).getBody();

        JsonNode object = toNode(response);
        this.checkResponse(object);
        JsonNode userInfoObject = getDataNode(object);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.ID))
                .avatar(getAvatarUrl(userInfoObject))
                .username(getStringValue(userInfoObject, Keys.USERINFO.USERNAME))
                .nickname(getStringValue(userInfoObject, "first_name") + " " + getStringValue(userInfoObject, "last_name"))
                .gender(AuthUserGender.UNKNOWN)
                .remark(getStringValue(userInfoObject, "bio"))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    private String getAvatarUrl(JsonNode userObj) {
        // image is a map data structure
        JsonNode jsonObject = getObjectNode(userObj, "image");
        if (Objects.isNull(jsonObject)) {
            return null;
        }

        JsonNode imageNode = getObjectNode(jsonObject, "60x60");
        return getStringValue(imageNode, Keys.USERINFO.URL);
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
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthPinterestScope.values())))
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("fields", "id,username,first_name,last_name,bio,image")
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (!containsKey(object, "status") && FAILURE.equals(getStringValue(object, "status"))) {
            throw new AuthException(getStringValue(object, Keys.USERINFO.MESSAGE));
        }
    }

}
