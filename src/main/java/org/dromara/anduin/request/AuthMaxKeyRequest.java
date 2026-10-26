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
 * MaxKey 登录。
 *
 * @author AprilWind
 */
public class AuthMaxKeyRequest extends AbstractAuthServerRequest {

    public AuthMaxKeyRequest(AuthConfig config) {
        super(config, AuthDefaultSource.MAXKEY);
    }

    public AuthMaxKeyRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.MAXKEY, authStateCache);
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
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));
        JsonNode object = parseResponse(httpClient()
                .get(userInfoUrl(authToken), null, header, false));
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(firstNotEmpty(object, "userId", Keys.USERINFO.USERID, Keys.USERINFO.SUB))
                .username(stringValue(object, Keys.USERINFO.USERNAME))
                .nickname(stringValue(object, "displayName"))
                .avatar(stringValue(object, Keys.USERINFO.AVATAR_URL))
                .blog(stringValue(object, "web_url"))
                .company(stringValue(object, "organization"))
                .location(stringValue(object, Keys.USERINFO.LOCATION))
                .email(stringValue(object, Keys.USERINFO.EMAIL))
                .remark(stringValue(object, "bio"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }
}
