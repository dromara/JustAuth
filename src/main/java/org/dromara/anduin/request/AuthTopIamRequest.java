package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.TokenUtils;
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
        Map<String, String> params = new HashMap<>(4);
        params.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2.CODE, authCallback.getCode());
        params.put(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri());

        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));

        String response = UnifiedHttpClient.getAdapter().postForm(tokenEndpoint(), params, header).getBody();

        JsonNode object = toNode(response);
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
