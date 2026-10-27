package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.TokenUtils;
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
                .email(getStringValue(object, Keys.USERINFO.EMAIL))
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
