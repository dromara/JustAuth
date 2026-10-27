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
        Map<String, String> params = authorizationCodeRequestParams(authCallback);

        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
        header.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

        JsonNode object = parseResponse(httpClient().postForm(tokenEndpoint(), params, header));
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
                .uuid(String.valueOf(getIntValue(object, "userId")))
                .username(getStringValue(object, Keys.USERINFO.USERNAME))
                .nickname(getStringValue(object, "displayName"))
                .avatar(getStringValue(object, Keys.USERINFO.AVATAR_URL))
                .blog(getStringValue(object, "web_url"))
                .company(getStringValue(object, "organization"))
                .location(getStringValue(object, Keys.USERINFO.LOCATION))
                .email(getStringValue(object, Keys.USERINFO.EMAIL))
                .remark(getStringValue(object, "bio"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }
}
