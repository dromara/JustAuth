package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.RecordingHttpAdapter;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(RecordingHttpAdapter.RESOURCE)
class CommonPlatformProtocolTest {
    private static final String REDIRECT = "https://client.example/callback";
    private RecordingHttpAdapter http;
    private final MemoryStateCache state = new MemoryStateCache();

    @BeforeEach void installTransport() { http = new RecordingHttpAdapter(); }
    @AfterEach void restoreTransport() { http.close(); }

    private AuthConfig config() {
        return AuthConfig.builder().clientId("test-client").clientSecret("test-secret")
                .redirectUri(REDIRECT).build();
    }

    @Test void githubAuthorizePreservesStateAndRequestedScopes() {
        AuthConfig config = config();
        config.setScopes(List.of("read:user", "user:email"));
        Map<String, String> query = authorize(new AuthGithubRequest(config, state),
                "https://github.com/login/oauth/authorize", "client_id");
        assertEquals("read:user user:email", query.get("scope"));
    }

    @Test void giteeAuthorizePreservesStateAndRequestedScopes() {
        AuthConfig config = config();
        config.setScopes(List.of("user_info", "emails"));
        Map<String, String> query = authorize(new AuthGiteeRequest(config, state),
                "https://gitee.com/oauth/authorize", "client_id");
        assertEquals("user_info emails", query.get("scope"));
    }

    @Test void wechatAuthorizeUsesAppIdAndLoginScope() {
        Map<String, String> query = authorize(new AuthWeChatOpenRequest(config(), state),
                "https://open.weixin.qq.com/connect/qrconnect", "appid");
        assertEquals("snsapi_login", query.get("scope"));
    }

    @Test void dingTalkAuthorizeUsesConsentAndCommaSeparatedScopes() {
        AuthConfig config = config();
        config.setScopes(List.of("openid", "corpid"));
        Map<String, String> query = authorize(new AuthDingTalkV2Request(config, state),
                "https://login.dingtalk.com/oauth2/challenge.htm", "client_id");
        assertEquals("openid,corpid", query.get("scope"));
        assertEquals("consent", query.get("prompt"));
    }

    @Test void missingStateIsGeneratedAndCachedForEveryPlatform() {
        for (AuthDefaultRequest request : List.of(new AuthGithubRequest(config(), state),
                new AuthGiteeRequest(config(), state), new AuthWeChatOpenRequest(config(), state),
                new AuthDingTalkV2Request(config(), state))) {
            String generated = query(request.authorize(null)).get("state");
            assertNotNull(generated);
            assertFalse(generated.isBlank());
            assertEquals(generated, state.get(generated));
        }
        assertTrue(http.requests().isEmpty());
    }

    @Test void githubExchangesTokenAndMapsUserWithAuthorizationHeader() {
        http.respond("access_token=" + "github-token" + "&token_type=" + "bearer" + "&scope=" + "read%3Auser");
        http.respond(developerUser("location"));
        AuthGithubRequest request = new AuthGithubRequest(config(), state);
        AuthToken token = request.getAccessToken(callback());
        assertEquals("github-token", token.getAccessToken());
        assertEquals("bearer", token.getTokenType());
        assertEquals("read:user", token.getScope());
        assertTokenRequest("POST", "https://github.com/login/oauth/access_token",
                oauthTokenQuery());
        AuthUser user = request.getUserInfo(token);
        assertDeveloper(user, token, "GITHUB");
        assertRequest(1, "GET", "https://api.github.com/user", Map.of());
        assertEquals("token github-token", http.requests().get(1).headers().get("Authorization"));
    }

    @Test void giteeExchangesJsonTokenAndMapsUserWithQueryToken() {
        http.respond("{\"access_token\":\"gitee-token\",\"token_type\":\"bearer\",\"expires_in\":3600,"
                + "\"refresh_token\":\"gitee-refresh\",\"scope\":\"user_info\"}");
        http.respond(developerUser("address"));
        AuthGiteeRequest request = new AuthGiteeRequest(config(), state);
        AuthToken token = request.getAccessToken(callback());
        assertEquals("gitee-token", token.getAccessToken());
        assertEquals("gitee-refresh", token.getRefreshToken());
        assertEquals(3600, token.getExpireIn());
        assertEquals("user_info", token.getScope());
        assertEquals("bearer", token.getTokenType());
        assertTokenRequest("POST", "https://gitee.com/oauth/token", oauthTokenQuery());
        assertDeveloper(request.getUserInfo(token), token, "GITEE");
        assertRequest(1, "GET", "https://gitee.com/api/v5/user", Map.of("access_token", "gitee-token"));
    }

    @Test void wechatExchangesTokenAndMapsOpenIdGenderAndUnionId() {
        http.respond(wechatToken("wechat-token", "refresh-token"));
        http.respond("{\"openid\":\"openid-1\",\"nickname\":\"Ada\",\"sex\":2,"
                + "\"country\":\"CN\",\"province\":\"ZJ\",\"city\":\"HZ\","
                + "\"headimgurl\":\"https://img.example/ada.png\",\"unionid\":\"union-1\",\"privilege\":[]}");
        AuthWeChatOpenRequest request = new AuthWeChatOpenRequest(config(), state);
        AuthToken token = request.getAccessToken(callback());
        assertEquals("wechat-token", token.getAccessToken());
        assertEquals("refresh-token", token.getRefreshToken());
        assertEquals(7200, token.getExpireIn());
        assertEquals("openid-1", token.getOpenId());
        assertTokenRequest("GET", "https://api.weixin.qq.com/sns/oauth2/access_token",
                Map.of("appid", "test-client", "secret", "test-secret", "code", "test-code",
                        "grant_type", "authorization_code"));
        AuthUser user = request.getUserInfo(token);
        assertEquals("openid-1", user.getUuid());
        assertEquals("Ada", user.getUsername());
        assertEquals("Ada", user.getNickname());
        assertEquals("CN-ZJ-HZ", user.getLocation());
        assertEquals("https://img.example/ada.png", user.getAvatar());
        assertEquals(AuthUserGender.FEMALE, user.getGender());
        assertEquals("union-1", token.getUnionId());
        assertEquals("WECHAT_OPEN", user.getSource());
        assertSame(token, user.getToken());
        assertNotNull(user.getRawUserInfo());
        assertRequest(1, "GET", "https://api.weixin.qq.com/sns/userinfo",
                Map.of("access_token", "wechat-token", "openid", "openid-1", "lang", "zh_CN"));
    }

    @Test void wechatRefreshUsesRefreshGrantAndReturnsNewToken() {
        http.respond(wechatToken("new-token", "new-refresh"));
        AuthToken old = AuthToken.builder().accessToken("old-token").refreshToken("old-refresh").build();
        var response = new AuthWeChatOpenRequest(config(), state).refresh(old);
        assertEquals(2000, response.getCode());
        assertEquals("new-token", response.getData().getAccessToken());
        assertEquals("new-refresh", response.getData().getRefreshToken());
        assertEquals("openid-1", response.getData().getOpenId());
        assertEquals(7200, response.getData().getExpireIn());
        assertEquals("old-token", old.getAccessToken());
        assertTokenRequest("GET", "https://api.weixin.qq.com/sns/oauth2/refresh_token",
                Map.of("appid", "test-client", "refresh_token", "old-refresh", "grant_type", "refresh_token"));
    }

    @Test void dingTalkExchangesTokenAndMapsUnionIdAndVisitorFlag() {
        http.respond("{\"accessToken\":\"ding-token\",\"expireIn\":7200,\"refreshToken\":\"ding-refresh\",\"corpId\":\"corp-1\"}");
        http.respond("{\"openId\":\"ding-open\",\"unionId\":\"ding-union\",\"nick\":\"Ada\","
                + "\"avatarUrl\":\"https://img.example/ada.png\",\"visitor\":true}");
        AuthDingTalkV2Request request = new AuthDingTalkV2Request(config(), state);
        AuthToken token = request.getAccessToken(callback());
        assertEquals("ding-token", token.getAccessToken());
        assertEquals("ding-refresh", token.getRefreshToken());
        assertEquals(7200, token.getExpireIn());
        assertEquals("corp-1", token.getCorpId());
        // Characterize the current query-only POST; migration to DingTalk's JSON contract is separate work.
        assertTokenRequest("POST", "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
                Map.of("code", "test-code", "clientId", "test-client", "clientSecret", "test-secret", "grantType", "authorization_code"));
        AuthUser user = request.getUserInfo(token);
        assertEquals("ding-union", user.getUuid());
        assertEquals("Ada", user.getUsername());
        assertEquals("Ada", user.getNickname());
        assertEquals("https://img.example/ada.png", user.getAvatar());
        assertTrue(user.isSnapshotUser());
        assertEquals("DINGTALK_V2", user.getSource());
        assertEquals("ding-open", token.getOpenId());
        assertEquals("ding-union", token.getUnionId());
        assertSame(token, user.getToken());
        assertNotNull(user.getRawUserInfo());
        assertRequest(1, "GET", "https://api.dingtalk.com/v1.0/contact/users/me", Map.of());
        assertEquals("ding-token", http.requests().get(1).headers().get("x-acs-dingtalk-access-token"));
    }

    @Test void githubRejectsTokenAndUserProviderErrors() {
        AuthGithubRequest request = new AuthGithubRequest(config(), state);
        http.respond("error=bad_verification_code&error_description=code+expired");
        assertEquals("code expired", assertThrows(AuthException.class, () -> request.getAccessToken(callback())).getMessage());
        http.respond("{\"error\":\"invalid_token\",\"error_description\":\"token expired\"}");
        assertEquals("token expired", assertThrows(AuthException.class,
                () -> request.getUserInfo(AuthToken.builder().accessToken("bad-token").build())).getMessage());
        assertEquals(2, http.requests().size());
    }

    @Test void giteeRejectsTokenAndUserProviderErrors() {
        AuthGiteeRequest request = new AuthGiteeRequest(config(), state);
        http.respond("{\"error\":\"invalid_grant\",\"error_description\":\"code expired\"}");
        assertEquals("code expired", assertThrows(AuthException.class, () -> request.getAccessToken(callback())).getMessage());
        http.respond("{\"error\":\"invalid_token\",\"error_description\":\"token expired\"}");
        assertEquals("token expired", assertThrows(AuthException.class,
                () -> request.getUserInfo(AuthToken.builder().accessToken("bad-token").build())).getMessage());
        assertEquals(2, http.requests().size());
    }

    @Test void wechatRejectsTokenUserAndRefreshProviderErrors() {
        AuthWeChatOpenRequest request = new AuthWeChatOpenRequest(config(), state);
        String error = "{\"errcode\":40029,\"errmsg\":\"invalid code\"}";
        http.respond(error);
        assertThrows(AuthException.class, () -> request.getAccessToken(callback()));
        http.respond(error);
        assertThrows(AuthException.class, () -> request.getUserInfo(AuthToken.builder().accessToken("bad-token").openId("openid-1").build()));
        http.respond(error);
        assertThrows(AuthException.class, () -> request.refresh(AuthToken.builder().refreshToken("bad-refresh").build()));
        assertEquals(3, http.requests().size());
    }

    @Test void dingTalkRejectsTokenResponseWithoutAccessToken() {
        http.respond("{\"code\":\"InvalidParameter\",\"message\":\"invalid authorization code\",\"requestid\":\"request-1\"}");
        AuthException error = assertThrows(AuthException.class,
                () -> new AuthDingTalkV2Request(config(), state).getAccessToken(callback()));
        assertTrue(error.getMessage().contains("InvalidParameter"));
        assertTrue(error.getMessage().contains("invalid authorization code"));
        assertEquals(1, http.requests().size());
    }

    private Map<String, String> authorize(AuthDefaultRequest request, String endpoint, String clientKey) {
        String url = request.authorize("csrf-state");
        assertEquals(endpoint, endpoint(url));
        Map<String, String> query = query(url);
        assertEquals("test-client", query.get(clientKey));
        assertEquals(REDIRECT, query.get("redirect_uri"));
        assertEquals("code", query.get("response_type"));
        assertEquals("csrf-state", query.get("state"));
        assertEquals("csrf-state", state.get("csrf-state"));
        assertFalse(query.containsKey("client_secret"));
        assertTrue(http.requests().isEmpty());
        return query;
    }

    private void assertTokenRequest(String method, String endpoint, Map<String, String> query) {
        assertEquals(1, http.requests().size());
        assertRequest(0, method, endpoint, query);
    }

    private void assertRequest(int index, String method, String endpoint, Map<String, String> query) {
        var recorded = http.requests().get(index);
        assertEquals(method, recorded.method());
        assertEquals(endpoint, endpoint(recorded.url()));
        assertEquals(query, query(recorded.url()));
        assertNull(recorded.body());
        assertTrue(recorded.params().isEmpty());
    }

    private static Map<String, String> oauthTokenQuery() {
        return Map.of("client_id", "test-client", "client_secret", "test-secret", "code", "test-code",
                "grant_type", "authorization_code", "redirect_uri", REDIRECT);
    }

    private static AuthCallback callback() { return AuthCallback.builder().code("test-code").build(); }

    private static String endpoint(String url) { return url.split("\\?", 2)[0]; }

    private static Map<String, String> query(String url) {
        String raw = URI.create(url).getRawQuery();
        Map<String, String> result = new HashMap<>();
        if (raw != null) {
            for (String pair : raw.split("&")) {
                String[] fields = pair.split("=", 2);
                result.put(URLDecoder.decode(fields[0], StandardCharsets.UTF_8),
                        fields.length == 1 ? "" : URLDecoder.decode(fields[1], StandardCharsets.UTF_8));
            }
        }
        return result;
    }

    private static String developerUser(String locationField) {
        return "{\"id\":42,\"login\":\"ada\",\"name\":\"Ada\",\"avatar_url\":\"https://img.example/ada.png\","
                + "\"blog\":\"https://ada.example\",\"company\":\"Engine\",\"" + locationField
                + "\":\"London\",\"email\":\"ada@example.com\",\"bio\":\"Mathematician\"}";
    }

    private static String wechatToken(String accessToken, String refreshToken) {
        return "{\"access_token\":\"" + accessToken + "\",\"expires_in\":7200,\"refresh_token\":\""
                + refreshToken + "\",\"openid\":\"openid-1\",\"scope\":\"snsapi_login\"}";
    }

    private static void assertDeveloper(AuthUser user, AuthToken token, String source) {
        assertEquals("42", user.getUuid());
        assertEquals("ada", user.getUsername());
        assertEquals("Ada", user.getNickname());
        assertEquals("https://img.example/ada.png", user.getAvatar());
        assertEquals("https://ada.example", user.getBlog());
        assertEquals("Engine", user.getCompany());
        assertEquals("London", user.getLocation());
        assertEquals("ada@example.com", user.getEmail());
        assertEquals("Mathematician", user.getRemark());
        assertEquals(AuthUserGender.UNKNOWN, user.getGender());
        assertEquals(source, user.getSource());
        assertSame(token, user.getToken());
        assertNotNull(user.getRawUserInfo());
    }

    private static final class MemoryStateCache implements AuthStateCache {
        private final Map<String, String> values = new HashMap<>();
        @Override public void cache(String key, String value) { values.put(key, value); }
        @Override public String get(String key) { return values.get(key); }
        @Override public boolean containsKey(String key) { return values.containsKey(key); }
        @Override public void expire(String key) { values.remove(key); }
    }
}
