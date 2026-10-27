package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthMiScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.log.Log;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import tools.jackson.databind.JsonNode;

import java.text.MessageFormat;

/**
 * 小米登录
 *
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.5.0
 */
public class AuthMiRequest extends AuthDefaultRequest {
    private static final String PREFIX = "&&&START&&&";

    public AuthMiRequest(AuthConfig config) {
        super(config, AuthDefaultSource.MI);
    }

    public AuthMiRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.MI, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return getToken(accessTokenUrl(authCallback.getCode()));
    }

    private AuthToken getToken(String accessTokenUrl) {
        String response = UnifiedHttpClient.getAdapter().get(accessTokenUrl).getBody();
        String jsonStr = response.replace(PREFIX, "");

        JsonNode accessTokenObject = toNode(jsonStr);
        validateResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .scope(getStringValue(accessTokenObject, Keys.OAUTH2.SCOPE))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .openId(getStringValue(accessTokenObject, "openId"))
                .macAlgorithm(getStringValue(accessTokenObject, "mac_algorithm"))
                .macKey(getStringValue(accessTokenObject, "mac_key"))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        // 获取用户信息
        String userResponse = doGetUserInfo(authToken);

        JsonNode userProfile = toNode(userResponse);
        if (Keys.RESPONSE_FIELDS.ERROR.equalsIgnoreCase(getStringValue(userProfile, Keys.RESPONSE_FIELDS.RESULT))) {
            throw new AuthException(getStringValue(userProfile, Keys.USERINFO.DESCRIPTION));
        }

        JsonNode userInfoObject = getDataNode(userProfile);

        AuthUser authUser = AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(authToken.getOpenId())
                .username(getStringValue(userInfoObject, "miliaoNick"))
                .nickname(getStringValue(userInfoObject, "miliaoNick"))
                .avatar(getStringValue(userInfoObject, "miliaoIcon"))
                .email(getStringValue(userInfoObject, "mail"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();

        // 获取用户邮箱手机号等信息
        String emailPhoneUrl = MessageFormat.format("{0}?clientId={1}&token={2}", "https://open.account.xiaomi.com/user/phoneAndEmail", config
                .getClientId(), authToken.getAccessToken());

        String emailResponse = UnifiedHttpClient.getAdapter().get(emailPhoneUrl).getBody();

        JsonNode userEmailPhone = toNode(emailResponse);
        if (!Keys.RESPONSE_FIELDS.ERROR.equalsIgnoreCase(getStringValue(userEmailPhone, Keys.RESPONSE_FIELDS.RESULT))) {
            JsonNode emailPhone = getDataNode(userEmailPhone);
            authUser.setEmail(getStringValue(emailPhone, Keys.USERINFO.EMAIL));
        } else {
            Log.warn("小米开发平台暂时不对外开放用户手机及邮箱信息的获取");
        }

        return authUser;
    }

    /**
     * 刷新access token （续期）
     *
     * @param authToken 登录成功后返回的Token信息
     * @return AuthResponse
     */
    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(refreshTokenUrl(authToken.getRefreshToken())))
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
                .queryParam("skip_confirm", "false")
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthMiScope.values())))
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
                .queryParam(Keys.PARAM.CLIENT_ID, config.getClientId())
                .queryParam("token", authToken.getAccessToken())
                .build();
    }
}
