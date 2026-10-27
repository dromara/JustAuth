package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AccessTokenUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * Teambition授权登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.9.0
 */
public class AuthTeambitionRequest extends AuthDefaultRequest {

    public AuthTeambitionRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TEAMBITION);
    }

    public AuthTeambitionRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TEAMBITION, authStateCache);
    }

    /**
     * @param authCallback 回调返回的参数
     * @return 所有信息
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> params = new HashMap<>(7);
        params.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.CODE);

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, false).getBody();

        JsonNode accessTokenObject = toNode(response);
        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();

        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.oauth2(accessToken));

        String response = UnifiedHttpClient.getAdapter().get(source.userInfo(), null, header, false).getBody();

        JsonNode userInfoObject = toNode(response);
        this.checkResponse(userInfoObject);

        authToken.setUid(getStringValue(userInfoObject, "_id"));

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "_id"))
                .username(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .avatar(getStringValue(userInfoObject, "avatarUrl"))
                .blog(getStringValue(userInfoObject, "website"))
                .location(getStringValue(userInfoObject, Keys.USERINFO.LOCATION))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        String uid = oldToken.getUid();
        String refreshToken = oldToken.getRefreshToken();

        Map<String, String> params = new HashMap<>(4);
        params.put("_userId", uid);
        params.put(Keys.OAUTH2.REFRESH_TOKEN, refreshToken);

        String response = UnifiedHttpClient.getAdapter().post(source.refresh(), params, false).getBody();

        JsonNode refreshTokenObject = toNode(response);
        this.checkResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(getStringValue(refreshTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                        .refreshToken(getStringValue(refreshTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                        .build())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JsonNode object) {
        if ((containsKey(object, Keys.USERINFO.MESSAGE) && containsKey(object, Keys.USERINFO.NAME))) {
            throw new AuthException(getStringValue(object, Keys.USERINFO.NAME) + ", " + getStringValue(object, Keys.USERINFO.MESSAGE));
        }
    }
}
