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
import org.dromara.anduin.utils.AccessTokenUtils;
import tools.jackson.databind.JsonNode;

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
        Map<String, String> params = authorizationCodeRequestParams(authCallback);

        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
        header.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

        JsonNode object = parseResponse(httpClient().postForm(tokenEndpoint(), params, header));
        return buildToken(object);
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        JsonNode object = getUserInfoObject(authToken);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(String.valueOf(getIntValue(object, Keys.USERINFO.ID)))
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
                .add(HttpHeaders.AUTHORIZATION, AccessTokenUtils.bearer(authToken.getAccessToken()));
        return parseResponse(httpClient()
                .get(userInfoUrl(authToken), null, header, false));
    }

}
