package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthQqScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import org.apache.commons.lang3.StringUtils;
import tools.jackson.databind.JsonNode;

import java.util.Map;

/**
 * qq登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @author yangkai.shen (<a href="https://xkcoding.com">...</a>)
 * @since 1.1.0
 */
public class AuthQqRequest extends AuthDefaultRequest {
    public AuthQqRequest(AuthConfig config) {
        super(config, AuthDefaultSource.QQ);
    }

    public AuthQqRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.QQ, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doGetAuthorizationCode(authCallback.getCode());
        return getAuthToken(response);
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        String response = UnifiedHttpClient.getAdapter().get(refreshTokenUrl(authToken.getRefreshToken())).getBody();
        return AuthResponse.<AuthToken>builder().code(AuthResponseStatus.SUCCESS.getCode()).data(getAuthToken(response)).build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String openId = this.getOpenId(authToken);
        String response = doGetUserInfo(authToken);
        JsonNode object = toNode(response);
        if (getIntValue(object, "ret") != 0) {
            throw new AuthException(getStringValue(object, "msg"));
        }
        String avatar = getStringValue(object, "figureurl_qq_2");
        if (StringUtils.isEmpty(avatar)) {
            avatar = getStringValue(object, "figureurl_qq_1");
        }

        String location = String.format("%s-%s", getStringValue(object, "province"), getStringValue(object, "city"));
        return AuthUser.builder()
                .rawUserInfo(object)
                .username(getStringValue(object, Keys.NICKNAME))
                .nickname(getStringValue(object, Keys.NICKNAME))
                .avatar(avatar)
                .location(location)
                .uuid(openId)
                .gender(AuthUserGender.getRealGender(getStringValue(object, Keys.GENDER)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 获取QQ用户的OpenId，支持自定义是否启用查询unionid的功能，如果启用查询unionid的功能，
     * 那就需要开发者先通过邮件申请unionid功能，参考链接 {@see http://wiki.connect.qq.com/unionid%E4%BB%8B%E7%BB%8D}
     *
     * @param authToken 通过{@link AuthQqRequest#getAccessToken(AuthCallback)}获取到的{@code authToken}
     * @return openId
     */
    private String getOpenId(AuthToken authToken) {
        String response = UnifiedHttpClient.getAdapter().get(UrlBuilder.fromBaseUrl("https://graph.qq.com/oauth2.0/me")
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.UNIONID, config.isUnionId() ? 1 : 0)
                .build()).getBody();
        String removePrefix = response.replace("callback(", "");
        String removeSuffix = removePrefix.replace(");", "");
        String openId = removeSuffix.trim();

        JsonNode object = toNode(openId);
        if (containsKey(object, Keys.ERROR)) {
            throw new AuthException(object.get(Keys.ERROR) + ":" + object.get(Keys.ERROR_DESCRIPTION));
        }
        authToken.setOpenId(getStringValue(object, Keys.OAUTH2_SCOPE__OPENID));
        if (containsKey(object, Keys.UNIONID)) {
            authToken.setUnionId(getStringValue(object, Keys.UNIONID));
        }
        return StringUtils.isEmpty(authToken.getUnionId()) ? authToken.getOpenId() : authToken.getUnionId();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户授权token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("oauth_consumer_key", config.getClientId())
                .queryParam(Keys.OAUTH2_SCOPE__OPENID, authToken.getOpenId())
                .build();
    }

    private AuthToken getAuthToken(String response) {
        Map<String, String> accessTokenObject = GlobalAuthUtils.parseStringToMap(response);
        if (!accessTokenObject.containsKey(Keys.OAUTH2__ACCESS_TOKEN) || accessTokenObject.containsKey(Keys.OAUTH2__CODE)) {
            throw new AuthException(accessTokenObject.get("msg"));
        }
        return AuthToken.builder()
                .accessToken(accessTokenObject.get(Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(Integer.parseInt(accessTokenObject.getOrDefault(Keys.OAUTH2__EXPIRES_IN, "0")))
                .refreshToken(accessTokenObject.get(Keys.OAUTH2__REFRESH_TOKEN))
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthQqScope.values())))
                .build();
    }
}
