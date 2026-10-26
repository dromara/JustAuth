package org.dromara.anduin.request;

import org.apache.commons.lang3.StringUtils;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.GlobalAuthUtils;
import tools.jackson.databind.JsonNode;

/**
 * 淘宝登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.1.0
 */
public class AuthTaobaoRequest extends AuthDefaultRequest {

    public AuthTaobaoRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TAOBAO);
    }

    public AuthTaobaoRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TAOBAO, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return AuthToken.builder().accessCode(authCallback.getCode()).build();
    }

    private AuthToken getAuthToken(JsonNode object) {
        this.checkResponse(object);

        return AuthToken.builder()
                .accessToken(getStringValue(object, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(object, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(object, Keys.OAUTH2.REFRESH_TOKEN))
                .idToken(getStringValue(object, Keys.OIDC.ID_TOKEN))
                .openId(getStringValue(object, "taobao_open_uid"))
                .uid(getStringValue(object, "taobao_user_id"))
                .tokenType(getStringValue(object, Keys.OAUTH2.TOKEN_TYPE))
                .build();
    }

    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doPostAuthorizationCode(authToken.getAccessCode());
        JsonNode accessTokenObject = toNode(response);
        if (containsKey(accessTokenObject, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(accessTokenObject, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
        authToken = this.getAuthToken(accessTokenObject);

        String nick = GlobalAuthUtils.urlDecode(getStringValue(accessTokenObject, "taobao_user_nick"));
        return AuthUser.builder()
                .rawUserInfo(accessTokenObject)
                .uuid(StringUtils.isEmpty(authToken.getUid()) ? authToken.getOpenId() : authToken.getUid())
                .username(nick)
                .nickname(nick)
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        String tokenUrl = refreshTokenUrl(oldToken.getRefreshToken());
        String response = UnifiedHttpClient.getAdapter().post(tokenUrl).getBody();
        JsonNode accessTokenObject = toNode(response);
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(this.getAuthToken(accessTokenObject))
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
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam("view", "web")
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }
}
