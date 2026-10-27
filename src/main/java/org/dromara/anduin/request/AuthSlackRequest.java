package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.apache.commons.collections4.CollectionUtils;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthSlackScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AccessTokenUtils;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

import java.util.List;

/**
 * slack登录, slack.com
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
public class AuthSlackRequest extends AuthDefaultRequest {

    public AuthSlackRequest(AuthConfig config) {
        super(config, AuthDefaultSource.SLACK);
    }

    public AuthSlackRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.SLACK, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

        String response = doGetAuthorizationCode(authCallback.getCode(), header);

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        JsonNode userObject = getObjectNode(accessTokenObject, "authed_user");
        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .uid(getStringValue(userObject, Keys.USERINFO.ID))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.bearer(authToken.getAccessToken()));

        String userInfo = UnifiedHttpClient.getAdapter()
                .get(userInfoUrl(authToken), null, header, false).getBody();
        JsonNode object = toNode(userInfo);
        this.checkResponse(object);
        JsonNode user = getObjectNode(object, Keys.USERINFO.USER);
        JsonNode profile = getObjectNode(user, Keys.OAUTH2.SCOPES.PROFILE);
        return AuthUser.builder()
                .rawUserInfo(user)
                .uuid(getStringValue(user, Keys.USERINFO.ID))
                .username(getStringValue(user, Keys.USERINFO.NAME))
                .nickname(getStringValue(user, "real_name"))
                .avatar(getStringValue(profile, "image_original"))
                .email(getStringValue(profile, Keys.USERINFO.EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<?> revoke(AuthToken authToken) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.bearer(authToken.getAccessToken()));
        String userInfo = UnifiedHttpClient.getAdapter()
                .get(source.revoke(), null, header, false).getBody();

        JsonNode object = toNode(userInfo);
        this.checkResponse(object);
        // 返回1表示取消授权成功，否则失败
        AuthResponseStatus status = getBooleanValue(object, "revoked") ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if (!getBooleanValue(object, "ok")) {
            String errorMsg = getStringValue(object, Keys.RESPONSE_FIELDS.ERROR);
            if (containsKey(object, "response_metadata")) {
                JsonNode responseMetadataObject = getObjectNode(object, "response_metadata");
                List<String> messages = responseMetadataObject.findValuesAsString("messages");
                if (CollectionUtils.isNotEmpty(messages)) {
                    errorMsg += "; " + String.join(",", messages);
                }
            }

            throw new AuthException(errorMsg);
        }
    }

    @Override
    public String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.USERINFO.USER, authToken.getUid())
                .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthSlackScope.values())))
                .build();
    }

    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2.CODE, code)
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .build();
    }
}
