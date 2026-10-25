package me.zhyd.oauth.request;

import com.google.common.net.HttpHeaders;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.http.HttpHeader;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.TokenUtils;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

/**
 * Gitea 登录。
 *
 * @author AprilWind
 */
public class AuthGiteaRequest extends AbstractAuthServerRequest {

    public AuthGiteaRequest(AuthConfig config) {
        super(config, AuthDefaultSource.GITEA);
    }

    public AuthGiteaRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.GITEA, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(8);
        form.put(Keys.OAUTH2.CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2.CLIENT_SECRET, config.getClientSecret());
        form.put(Keys.OAUTH2.GRANT_TYPE, Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        form.put(Keys.OAUTH2.CODE, authCallback.getCode());
        form.put(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri());

        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
        JsonNode object = parseResponse(httpClient()
                .postForm(tokenEndpoint(), form, header));
        return buildToken(object);
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        JsonNode object = getUserInfoObject(authToken);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(firstNotEmpty(object, Keys.USERINFO.SUB, Keys.USERINFO.ID))
                .username(firstNotEmpty(object, Keys.USERINFO.NAME, "login"))
                .nickname(firstNotEmpty(object, "preferred_username", "full_name", "login"))
                .avatar(firstNotEmpty(object, "picture", Keys.USERINFO.AVATAR_URL))
                .email(stringValue(object, Keys.USERINFO.EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    private JsonNode getUserInfoObject(AuthToken authToken) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));
        return parseResponse(httpClient()
                .get(userInfoUrl(authToken), null, header, false));
    }

}
