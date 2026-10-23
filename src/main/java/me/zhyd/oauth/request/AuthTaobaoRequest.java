package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.GlobalAuthUtils;

import org.apache.commons.lang3.StringUtils;
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
                .accessToken(getStringValue(object, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(object, Keys.OAUTH2__EXPIRES_IN))
                .refreshToken(getStringValue(object, Keys.OAUTH2__REFRESH_TOKEN))
                .idToken(getStringValue(object, Keys.OIDC__ID_TOKEN))
                .openId(getStringValue(object, "taobao_open_uid"))
                .uid(getStringValue(object, "taobao_user_id"))
                .tokenType(getStringValue(object, Keys.OAUTH2__TOKEN_TYPE))
                .build();
    }

    private void checkResponse(JsonNode object) {
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(getStringValue(object, Keys.ERROR_DESCRIPTION));
        }
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doPostAuthorizationCode(authToken.getAccessCode());
        JsonNode accessTokenObject = toNode(response);
        if (containsKey(accessTokenObject, Keys.ERROR)) {
            throw new AuthException(getStringValue(accessTokenObject, Keys.ERROR_DESCRIPTION));
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
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam("view", "web")
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
                .build();
    }
}
