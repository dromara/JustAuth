package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.scope.AuthDingTalkScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.JsonUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * 新版钉钉二维码登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.7
 */
public class AuthDingTalkV2Request extends AuthDefaultRequest {

    public AuthDingTalkV2Request(AuthConfig config) {
        super(config, AuthDefaultSource.DINGTALK_V2);
    }

    public AuthDingTalkV2Request(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.DINGTALK_V2, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.OAUTH2__CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2__SCOPE, this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthDingTalkScope.values())))
                .queryParam(Keys.OAUTH2__REDIRECT_URI, GlobalAuthUtils.urlEncode(config.getRedirectUri()))
                .queryParam("prompt", "consent")
                .queryParam("org_type", config.getDingTalkOrgType())
                .queryParam("corpId", config.getDingTalkCorpId())
                .queryParam("exclusiveLogin", config.isDingTalkExclusiveLogin())
                .queryParam("exclusiveCorpId", config.getDingTalkExclusiveCorpId())
                .queryParam(Keys.OAUTH2__STATE, getRealState(state))
                .build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> params = new HashMap<>();
        params.put("grantType", Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        params.put(Keys.PARAM__CLIENT_ID, config.getClientId());
        params.put(Keys.PARAM__CLIENT_SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2__CODE, authCallback.getCode());

        String response = UnifiedHttpClient.getAdapter().post(this.source.accessToken(), JsonUtils.toJson(params)).getBody();

        JsonNode accessTokenObject = toNode(response);
        if (!containsKey(accessTokenObject, "accessToken")) {
            throw new AuthException(JsonUtils.toJson(response), source);
        }

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, "accessToken"))
                .expireIn(getIntValue(accessTokenObject, "expireIn"))
                .refreshToken(getStringValue(accessTokenObject, "refreshToken"))
                .corpId(getStringValue(accessTokenObject, "corpId"))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader();
        header.add("x-acs-dingtalk-access-token", authToken.getAccessToken());

        String response = UnifiedHttpClient.getAdapter().get(this.source.userInfo(), null, header, false).getBody();

        JsonNode userInfoObject = toNode(response);

        authToken.setOpenId(getStringValue(userInfoObject, "openId"));
        authToken.setUnionId(getStringValue(userInfoObject, "unionId"));

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "unionId"))
                .username(getStringValue(userInfoObject, "nick"))
                .nickname(getStringValue(userInfoObject, "nick"))
                .avatar(getStringValue(userInfoObject, "avatarUrl"))
                .snapshotUser(getBooleanValue(userInfoObject, "visitor"))
                .token(authToken)
                .source(source.toString())
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
                .queryParam(Keys.OAUTH2__CODE, code)
                .queryParam(Keys.PARAM__CLIENT_ID, config.getClientId())
                .queryParam(Keys.PARAM__CLIENT_SECRET, config.getClientSecret())
                .queryParam("grantType", Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
                .build();
    }
}
