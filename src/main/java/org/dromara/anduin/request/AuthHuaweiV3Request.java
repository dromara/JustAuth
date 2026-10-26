package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.enums.scope.AuthHuaweiV3Scope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpConstants;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.PkceUtil;

import org.apache.commons.lang3.StringUtils;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.dromara.anduin.enums.AuthResponseStatus.SUCCESS;

/**
 * 华为授权登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @version 1.0
 * @since 1.16.7
 */
public class AuthHuaweiV3Request extends AuthDefaultRequest {

    public AuthHuaweiV3Request(AuthConfig config) {
        super(config, AuthDefaultSource.HUAWEI_V3);
    }

    public AuthHuaweiV3Request(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.HUAWEI_V3, authStateCache);
    }

    /**
     * 获取access token
     *
     * @param authCallback 授权成功后的回调参数
     * @return token
     * @see AuthDefaultRequest#authorize()
     * @see AuthDefaultRequest#authorize(String)
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> params = new HashMap<>(8);
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri());

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(authCallback.getState());
            String codeVerifier = this.authStateCache.get(cacheKey);
            params.put("code_verifier", codeVerifier);
        }

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpConstants.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, httpHeader, false).getBody();

        return getAuthToken(response);
    }

    /**
     * 使用token换取用户信息
     *
     * @param authToken token信息
     * @return 用户信息
     * @see AuthDefaultRequest#getAccessToken(AuthCallback)
     */
    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String idToken = authToken.getIdToken();
        if (StringUtils.isEmpty(idToken)) {
            Map<String, String> params = new HashMap<>(7);
            params.put(Keys.OAUTH2.ACCESS_TOKEN, authToken.getAccessToken());
            params.put("getNickName", "1");
            params.put("nsp_svc", "GOpen.User.getInfo");

            HttpHeader httpHeader = new HttpHeader();
            httpHeader.add(HttpConstants.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

            String response = UnifiedHttpClient.getAdapter().post(source.userInfo(), params, httpHeader, false).getBody();

            JsonNode userInfoObject = toNode(response);
            this.checkResponse(userInfoObject);

            return AuthUser.builder()
                    .rawUserInfo(userInfoObject)
                    .uuid(getStringValue(userInfoObject, "unionID"))
                    .username(getStringValue(userInfoObject, Keys.USERINFO.DISPLAY_NAME))
                    .nickname(getStringValue(userInfoObject, Keys.USERINFO.DISPLAY_NAME))
                    .gender(AuthUserGender.UNKNOWN)
                    .avatar(getStringValue(userInfoObject, "headPictureURL"))
                    .token(authToken)
                    .source(source.toString())
                    .build();
        }

        String payload = new String(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]), StandardCharsets.UTF_8);

        JsonNode userInfoObject = toNode(payload);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.SUB))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NICKNAME))
                .gender(AuthUserGender.UNKNOWN)
                .avatar(getStringValue(userInfoObject, Keys.USERINFO.PICTURE))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 刷新access token （续期）
     *
     * @param authToken 登录成功后返回的Token信息
     * @return AuthResponse
     */
    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        Map<String, String> form = new HashMap<>(7);
        form.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());
        form.put(Keys.OAUTH2.REFRESH_TOKEN, authToken.getRefreshToken());
        form.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.REFRESH_TOKEN);

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpConstants.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
        String response = UnifiedHttpClient.getAdapter().post(source.refresh(), form, httpHeader, false).getBody();
        return AuthResponse.<AuthToken>builder().code(SUCCESS.getCode()).data(getAuthToken(response)).build();
    }

    private AuthToken getAuthToken(String response) {
        JsonNode object = toNode(response);

        this.checkResponse(object);

        return AuthToken.builder()
                .accessToken(getStringValue(object, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(object, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(object, Keys.OAUTH2.REFRESH_TOKEN))
                .idToken(getStringValue(object, Keys.OIDC.ID_TOKEN))
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
        String realState = getRealState(state);
        UrlBuilder builder = UrlBuilder.fromBaseUrl(super.authorize(realState))
                .queryParam("access_type", "offline")
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthHuaweiV3Scope.values())));

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(realState);
            String codeVerifier = PkceUtil.generateCodeVerifier();
            String codeChallengeMethod = "S256";
            String codeChallenge = PkceUtil.generateCodeChallenge(codeChallengeMethod, codeVerifier);
            builder.queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", codeChallengeMethod);
            // 缓存 codeVerifier
            this.authStateCache.cache(cacheKey, codeVerifier);
        }
        return builder.build();
    }

    /**
     * 校验响应结果
     *
     * @param object 接口返回的结果
     */
    private void checkResponse(JsonNode object) {
        if (containsKey(object, "NSP_STATUS")) {
            throw new AuthException(getStringValue(object, Keys.RESPONSE_FIELDS.ERROR));
        }
        if (containsKey(object, Keys.RESPONSE_FIELDS.ERROR)) {
            throw new AuthException(getStringValue(object, "sub_error") + ":" + getStringValue(object, Keys.RESPONSE_FIELDS.ERROR_DESCRIPTION));
        }
    }


}
