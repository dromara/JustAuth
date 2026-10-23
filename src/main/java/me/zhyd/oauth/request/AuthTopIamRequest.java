package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.http.UrlBuilder;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.TokenUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TopIAM 登录。
 *
 * @author AprilWind
 */
public class AuthTopIamRequest extends AbstractAuthServerRequest {

    private static final List<String> DEFAULT_SCOPES = List.of(
            Keys.OAUTH2.SCOPES.OPENID, Keys.OAUTH2.SCOPES.PROFILE, Keys.OAUTH2.SCOPES.EMAIL);

    public AuthTopIamRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TOPIAM);
    }

    public AuthTopIamRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TOPIAM, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2.SCOPE, getScopes(" ", true, DEFAULT_SCOPES))
                .build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(4);
        form.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        form.put(Keys.OAUTH2.CODE, authCallback.getCode());
        form.put(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri());

        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));
        JsonNode object = parseResponse(httpClient()
                .postForm(tokenEndpoint(), form, header));
        return buildToken(object);
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));
        JsonNode object = parseResponse(httpClient()
                .get(userInfoUrl(authToken), null, header, false));
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(stringValue(object, Keys.USERINFO.SUB))
                .username(stringValue(object, "preferred_username"))
                .nickname(firstNotEmpty(object, Keys.USERINFO.NICKNAME, Keys.USERINFO.NAME, "preferred_username"))
                .avatar(stringValue(object, "picture"))
                .email(stringValue(object, Keys.USERINFO.EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }
}
