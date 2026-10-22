package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.UnifiedHttpClient;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.JsonUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import org.apache.commons.lang3.StringUtils;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * 企业微信登录父类
 * </p>
 *
 * @author liguanhua (347826496(a)qq.com)
 * @since 1.15.9
 */
public abstract class AbstractAuthWeChatEnterpriseRequest extends AuthDefaultRequest {

    protected AbstractAuthWeChatEnterpriseRequest(AuthConfig config, AuthSource source) {
        super(config, source);
    }


    protected AbstractAuthWeChatEnterpriseRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        super(config, source, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doGetAuthorizationCode(accessTokenUrl(null));

        JsonNode object = this.checkResponse(response);

        return AuthToken.builder()
                .accessToken(getStringValue(object, Keys.OAUTH2__ACCESS_TOKEN))
                .expireIn(getIntValue(object, Keys.OAUTH2__EXPIRES_IN))
                .code(authCallback.getCode())
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);
        JsonNode object = this.checkResponse(response);

        // 返回 OpenId 或其他，均代表非当前企业用户，不支持
        if (!containsKey(object, "UserId")) {
            throw new AuthException(AuthResponseStatus.UNIDENTIFIED_PLATFORM, source);
        }
        String userId = getStringValue(object, "UserId");
        String userTicket = getStringValue(object, "user_ticket");
        JsonNode userDetail = getUserDetail(authToken.getAccessToken(), userId, userTicket);

        return AuthUser.builder()
                .rawUserInfo(userDetail)
                .username(getStringValue(userDetail, Keys.NAME))
                .nickname(getStringValue(userDetail, "alias"))
                .avatar(getStringValue(userDetail, Keys.AVATAR))
                .location(getStringValue(userDetail, Keys.OAUTH2_SCOPE__ADDRESS))
                .email(getStringValue(userDetail, Keys.OAUTH2_SCOPE__EMAIL))
                .uuid(userId)
                .gender(AuthUserGender.getWechatRealGender(getStringValue(userDetail, Keys.GENDER)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 校验请求结果
     *
     * @param response 请求结果
     * @return 如果请求结果正常，则返回JSONObject
     */
    private JsonNode checkResponse(String response) {
        JsonNode object = toNode(response);

        if (containsKey(object, Keys.VARIANT__ERRCODE) && getIntValue(object, Keys.VARIANT__ERRCODE) != 0) {
            throw new AuthException(getStringValue(object, Keys.VARIANT__ERRMSG), source);
        }

        return object;
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
                .queryParam("corpid", config.getClientId())
                .queryParam("corpsecret", config.getClientSecret())
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
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2__CODE, authToken.getCode())
                .build();
    }

    /**
     * 用户详情
     *
     * @param accessToken accessToken
     * @param userId      企业内用户id
     * @param userTicket  成员票据，用于获取用户信息或敏感信息
     * @return 用户详情
     */
    private JsonNode getUserDetail(String accessToken, String userId, String userTicket) {
        // 用户基础信息
        String userInfoUrl = UrlBuilder.fromBaseUrl("https://qyapi.weixin.qq.com/cgi-bin/user/get")
                .queryParam(Keys.OAUTH2__ACCESS_TOKEN, accessToken)
                .queryParam(Keys.USERID, userId)
                .build();
        String userInfoResponse = UnifiedHttpClient.getAdapter().get(userInfoUrl).getBody();
        JsonNode userInfoObject = checkResponse(userInfoResponse);

        // 用户敏感信息
        if (StringUtils.isNotEmpty(userTicket)) {
            String userDetailUrl = UrlBuilder.fromBaseUrl("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail")
                    .queryParam(Keys.OAUTH2__ACCESS_TOKEN, accessToken)
                    .build();
            Map<String, Object> param = new HashMap<>();
            param.put("user_ticket", userTicket);
            String userDetailResponse = UnifiedHttpClient.getAdapter().post(userDetailUrl, JsonUtils.toJson(param)).getBody();
            JsonNode userDetail = checkResponse(userDetailResponse);

            ObjectNode userInfoObjectNode = (ObjectNode) userInfoObject;

            ObjectNode userDetailObjectNode = (ObjectNode) userDetail;
            userInfoObjectNode.setAll(userDetailObjectNode);
        }
        return userInfoObject;
    }

}
