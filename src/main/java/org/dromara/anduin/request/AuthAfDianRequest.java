package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import tools.jackson.databind.JsonNode;

/**
 * 爱发电
 *
 * @author handy
 */
public class AuthAfDianRequest extends AuthDefaultRequest {

    public AuthAfDianRequest(AuthConfig config) {
        super(config, AuthDefaultSource.AFDIAN);
    }

    public AuthAfDianRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.AFDIAN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());

        JsonNode accessTokenObject = toNode(response);

        JsonNode data = getDataNode(accessTokenObject);
        String userId = getStringValue(data, Keys.USERINFO.USER_ID);

        return AuthToken.builder().userId(userId).build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        return AuthUser.builder()
                .uuid(authToken.getUserId())
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {

        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.SCOPE, "basic")
                .queryParam(Keys.OAUTH2.CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }

}
