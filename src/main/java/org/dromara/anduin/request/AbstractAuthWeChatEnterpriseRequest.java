package org.dromara.anduin.request;

import org.apache.commons.lang3.StringUtils;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.JsonUtils;
import tools.jackson.databind.JsonNode;

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

        JsonNode accessTokenObject = this.checkResponse(response);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .code(authCallback.getCode())
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);

        JsonNode responseObject = this.checkResponse(response);
        // 兼容 userid / UserId
        String userId = null;
        // 返回 OpenId 或其他，均代表非当前企业用户，不支持
        if (containsKey(responseObject, "userid")) {
            userId = getStringValue(responseObject, "userid");
        } else if (containsKey(responseObject, "UserId")) {
            userId = getStringValue(responseObject, "UserId");
        }
        if (userId == null) {
            throw new AuthException(AuthResponseStatus.UNIDENTIFIED_PLATFORM, source);
        }
        String userTicket = getStringValue(responseObject, "user_ticket");

        JsonNode userInfoObject = getUserDetail(authToken.getAccessToken(), userId, userTicket);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .nickname(getStringValue(userInfoObject, "alias"))
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.AVATAR))
                .location(getStringValue(userInfoObject, Keys.USERINFO.ADDRESS))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .uuid(userId)
                .gender(AuthUserGender.getWechatRealGender(getStringValue(userInfoObject, Keys.USERINFO.GENDER)))
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

        if (containsKey(object, Keys.RESPONSE_FIELDS.ERRCODE) && getIntValue(object, Keys.RESPONSE_FIELDS.ERRCODE) != 0) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERRMSG), source);
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
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.OAUTH2.CODE, authToken.getCode())
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
                .queryParam(Keys.OAUTH2.ACCESS_TOKEN, accessToken)
                .queryParam(Keys.USERINFO.USERID, userId)
                .build();
        String userInfoResponse = UnifiedHttpClient.getAdapter().get(userInfoUrl).getBody();
        JsonNode userInfoObject = checkResponse(userInfoResponse);

        // 用户敏感信息
        if (StringUtils.isNotEmpty(userTicket)) {
            String userDetailUrl = UrlBuilder.fromBaseUrl("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail")
                    .queryParam(Keys.OAUTH2.ACCESS_TOKEN, accessToken)
                    .build();
            Map<String, Object> param = new HashMap<>();
            param.put("user_ticket", userTicket);
            String userDetailResponse = UnifiedHttpClient.getAdapter().post(userDetailUrl, JsonUtils.toJson(param)).getBody();

            JsonNode userDetail = checkResponse(userDetailResponse);

            userInfoObject.asObject().setAll(userDetail.asObject());
        }
        return userInfoObject;
    }

}
