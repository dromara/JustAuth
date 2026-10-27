package org.dromara.anduin.request;

import com.google.common.net.HttpHeaders;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.constant.MediaType;
import org.dromara.anduin.http.HttpConstants;
import org.dromara.anduin.http.HttpHeader;
import org.dromara.anduin.http.UnifiedHttpClient;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.GlobalAuthUtils;
import org.dromara.anduin.utils.MapUtil;
import tools.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;

import static org.dromara.anduin.config.AuthDefaultSource.TWITTER;
import static org.dromara.anduin.utils.GlobalAuthUtils.generateTwitterSignature;
import static org.dromara.anduin.utils.GlobalAuthUtils.urlEncode;

/**
 * Twitter登录
 *
 * @author hongwei.peng (pengisgood(at)gmail(dot)com)
 * @since 1.13.0
 */
public class AuthTwitterRequest extends AuthDefaultRequest {

    private static final String PREAMBLE = "OAuth";
    static final String OAUTH_SIGNATURE = "oauth_signature";

    public AuthTwitterRequest(AuthConfig config) {
        super(config, TWITTER);
    }

    public AuthTwitterRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, TWITTER, authStateCache);
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        AuthToken token = this.getRequestToken();
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam("oauth_token", token.getOauthToken())
                .build();
    }

    /**
     * Obtaining a request token
     * <a href="https://developer.twitter.com/en/docs/twitter-for-websites/log-in-with-twitter/guides/implementing-sign-in-with-twitter">...</a>
     *
     * @return request token
     */
    public AuthToken getRequestToken() {
        String baseUrl = "https://api.twitter.com/oauth/request_token";

        Map<String, String> oauthParams = buildOauthParams();
        oauthParams.put("oauth_callback", config.getRedirectUri());
        oauthParams.put(OAUTH_SIGNATURE, generateTwitterSignature(oauthParams, "POST", baseUrl, config.getClientSecret(), null));
        String headerString = buildHeader(oauthParams);

        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.AUTHORIZATION, headerString);
        header.add(HttpHeaders.USER_AGENT, "'JustAuth' HTTP Client Simple-Http");

        String requestToken = UnifiedHttpClient.getAdapter().post(baseUrl, null, header).getBody();

        Map<String, String> res = MapUtil.parseStringToMap(requestToken, false);

        return AuthToken.builder()
                .oauthToken(res.get("oauth_token"))
                .oauthTokenSecret(res.get("oauth_token_secret"))
                .oauthCallbackConfirmed(Boolean.valueOf(res.get("oauth_callback_confirmed")))
                .build();
    }

    /**
     * Convert request token to access token
     * <a href="https://developer.twitter.com/en/docs/twitter-for-websites/log-in-with-twitter/guides/implementing-sign-in-with-twitter">...</a>
     *
     * @return access token
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> oauthParams = buildOauthParams();
        oauthParams.put("oauth_token", authCallback.getOauth_token());
        oauthParams.put("oauth_verifier", authCallback.getOauth_verifier());
        oauthParams.put(OAUTH_SIGNATURE, generateTwitterSignature(oauthParams, "POST", source.accessToken(), config.getClientSecret(), authCallback
                .getOauth_token()));
        String headerString = buildHeader(oauthParams);

        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.AUTHORIZATION, headerString);
        header.add(HttpConstants.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

        Map<String, String> params = new HashMap<>(3);
        params.put("oauth_verifier", authCallback.getOauth_verifier());

        String response = UnifiedHttpClient.getAdapter().post(source.accessToken(), params, header, false).getBody();

        Map<String, String> requestToken = MapUtil.parseStringToMap(response, false);

        return AuthToken.builder()
                .oauthToken(requestToken.get("oauth_token"))
                .oauthTokenSecret(requestToken.get("oauth_token_secret"))
                .userId(requestToken.get(Keys.USERINFO.USER_ID))
                .screenName(requestToken.get(Keys.USERINFO.SCREENNAME))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        Map<String, String> queryParams = new HashMap<>(5);
        queryParams.put("include_entities", Boolean.toString(true));
        queryParams.put("include_email", Boolean.toString(true));

        Map<String, String> oauthParams = buildOauthParams();
        oauthParams.put("oauth_token", authToken.getOauthToken());

        Map<String, String> params = new HashMap<>(oauthParams);
        params.putAll(queryParams);
        oauthParams.put(OAUTH_SIGNATURE, generateTwitterSignature(params, "GET", source.userInfo(), config.getClientSecret(), authToken.getOauthTokenSecret()));
        String headerString = buildHeader(oauthParams);

        HttpHeader header = new HttpHeader();
        header.add(HttpHeaders.AUTHORIZATION, headerString);

        String response = UnifiedHttpClient.getAdapter().get(userInfoUrl(authToken), null, header, false).getBody();
        JsonNode userInfoObject = toNode(response);

        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, "id_str"))
                .username(getStringValue(userInfoObject, Keys.USERINFO.SCREENNAME))
                .nickname(getStringValue(userInfoObject, Keys.USERINFO.NAME))
                .remark(getStringValue(userInfoObject, Keys.USERINFO.DESCRIPTION))
                .avatar(getStringValue(userInfoObject, "profile_image_url_https"))
                .blog(getStringValue(userInfoObject, Keys.USERINFO.URL))
                .location(getStringValue(userInfoObject, Keys.USERINFO.LOCATION))
                .avatar(getStringValue(userInfoObject, "profile_image_url"))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .source(source.toString())
                .token(authToken)
                .build();
    }

    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam("include_entities", true)
                .queryParam("include_email", true)
                .build();
    }

    private Map<String, String> buildOauthParams() {
        Map<String, String> params = new HashMap<>(12);
        params.put("oauth_consumer_key", config.getClientId());
        params.put("oauth_nonce", GlobalAuthUtils.generateNonce(32));
        params.put("oauth_signature_method", "HMAC-SHA1");
        params.put("oauth_timestamp", GlobalAuthUtils.getTimestamp());
        params.put("oauth_version", "1.0");
        return params;
    }

    private String buildHeader(Map<String, String> oauthParams) {
        final StringBuilder sb = new StringBuilder(PREAMBLE + " ");

        for (Map.Entry<String, String> param : oauthParams.entrySet()) {
            sb.append(param.getKey()).append("=\"").append(urlEncode(param.getValue())).append('"').append(", ");
        }

        return sb.deleteCharAt(sb.length() - 2).toString();
    }
}
