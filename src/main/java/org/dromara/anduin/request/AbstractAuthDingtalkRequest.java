package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.GlobalAuthUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * 钉钉登录抽象类，负责处理使用钉钉账号登录第三方网站和扫码登录第三方网站两种钉钉的登录方式
 * </p>
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
public abstract class AbstractAuthDingtalkRequest extends AuthDefaultRequest {

    protected AbstractAuthDingtalkRequest(AuthConfig config, AuthSource source) {
        super(config, source);
    }


    protected AbstractAuthDingtalkRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        super(config, source, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return AuthToken.builder().accessCode(authCallback.getCode()).build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String code = authToken.getAccessCode();

        Map<String, String> params = new HashMap<>();
        params.put("tmp_auth_code", code);

        String response = UnifiedHttpClient.getAdapter().post(userInfoUrl(authToken), params, false).getBody();

        JsonNode responseObject = toNode(response);
        if (getIntValue(responseObject, Keys.RESPONSE_FIELDS.ERRCODE) != 0) {
            throw new AuthException(getStringValue(responseObject, Keys.RESPONSE_FIELDS.ERRMSG));
        }

        JsonNode userInfoObject = getObjectNode(responseObject, "user_info");
        AuthToken token = AuthToken.builder()
                .openId(getStringValue(userInfoObject, Keys.OAUTH2.SCOPES.OPENID))
                .unionId(getStringValue(userInfoObject, Keys.USERINFO.UNIONID))
                .build();
        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.UNIONID))
                .nickname(getStringValue(userInfoObject, "nick"))
                .username(getStringValue(userInfoObject, "nick"))
                .gender(AuthUserGender.UNKNOWN)
                .source(source.toString())
                .token(token)
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
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2.SCOPE, "snsapi_login")
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
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
        // 根据timestamp, appSecret计算签名值
        String timestamp = System.currentTimeMillis() + "";
        String urlEncodeSignature = GlobalAuthUtils.generateDingTalkSignature(config.getClientSecret(), timestamp);

        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam("signature", urlEncodeSignature)
                .queryParam("timestamp", timestamp)
                .queryParam("accessKey", config.getClientId())
                .build();
    }

}
