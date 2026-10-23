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
        form.put(Keys.OAUTH2__CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2__CLIENT_SECRET, config.getClientSecret());
        form.put(Keys.OAUTH2__GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        form.put(Keys.OAUTH2__CODE, authCallback.getCode());
        form.put(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri());
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
                .uuid(firstNotEmpty(object, "userId", Keys.USERID, "sub"))
                .username(stringValue(object, Keys.USERNAME))
                .nickname(stringValue(object, "displayName"))
                .avatar(stringValue(object, Keys.AVATAR_URL))
                .blog(stringValue(object, "web_url"))
                .company(stringValue(object, "organization"))
                .location(stringValue(object, Keys.LOCATION))
                .email(stringValue(object, Keys.OAUTH2_SCOPE__EMAIL))
                .remark(stringValue(object, "bio"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }
}
