package me.zhyd.oauth.request;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import me.zhyd.oauth.AuthRequestBuilder;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.http.AdapterHttpResponse;
import me.zhyd.oauth.http.HttpConfig;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.Base64Utils;
import me.zhyd.oauth.utils.JsonUtils;
import org.junit.Assert;
import org.junit.Test;
import tools.jackson.databind.JsonNode;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 私有化部署平台的协议与兼容性回归测试。
 *
 * @author AprilWind
 */
public class AuthServerRequestTest {

    @Test
    public void shouldBuildGiteaRequestAndNormalizeServerUrl() {
        AuthRequest request = AuthRequestBuilder.builder()
                .source("gitea")
                .authConfig(config("https://gitea.example.com///"))
                .build();

        Assert.assertTrue(request instanceof AuthGiteaRequest);
        String authorizeUrl = request.authorize("state");
        Assert.assertTrue(authorizeUrl.startsWith("https://gitea.example.com/login/oauth/authorize?"));
        Assert.assertFalse(authorizeUrl.contains(".com//login"));
    }

    @Test
    public void shouldBuildMaxKeyRequest() {
        AuthRequest request = AuthRequestBuilder.builder()
                .source("MAXKEY")
                .authConfig(config("https://maxkey.example.com"))
                .build();

        Assert.assertTrue(request instanceof AuthMaxKeyRequest);
        Assert.assertTrue(request.authorize("state")
                .startsWith("https://maxkey.example.com/sign/authz/oauth/v20/authorize?"));
    }

    @Test
    public void shouldBuildTopIamRequestWithDefaultScopes() {
        AuthRequest request = AuthRequestBuilder.builder()
                .source("topiam")
                .authConfig(config("https://topiam.example.com/api/v1/authorize/app"))
                .build();

        Assert.assertTrue(request instanceof AuthTopIamRequest);
        String authorizeUrl = request.authorize("state");
        Assert.assertTrue(authorizeUrl.startsWith(
                "https://topiam.example.com/api/v1/authorize/app/oauth2/auth?"));
        Assert.assertTrue(authorizeUrl.contains("scope=openid%20profile%20email"));
    }

    @Test
    public void shouldUseConfiguredTopIamScopes() {
        AuthConfig config = config("https://topiam.example.com");
        config.setScopes(List.of("openid", "phone"));

        String authorizeUrl = new AuthTopIamRequest(config).authorize("state");

        Assert.assertTrue(authorizeUrl.contains("scope=openid%20phone"));
    }

    @Test(expected = AuthException.class)
    public void shouldRejectInvalidServerUrl() {
        new AuthGiteaRequest(config("gitea.internal"));
    }

    @Test
    public void shouldRejectMalformedServerUrls() {
        for (String serverUrl : List.of(
                "http://",
                "https://",
                "http%3A%2F%2Fgitea.example.com",
                "https://gitea.example.com?tenant=1",
                "https://gitea.example.com#fragment")) {
            try {
                new AuthGiteaRequest(config(serverUrl));
                Assert.fail("Expected invalid serverUrl: " + serverUrl);
            } catch (AuthException exception) {
                Assert.assertNotNull(exception.getMessage());
            }
        }
    }

    @Test
    public void shouldPostGiteaTokenAsFormBodyAndKeepOAuthError() throws Exception {
        HttpServer server = createServer();
        server.createContext("/login/oauth/access_token", exchange -> {
            Map<String, String> form = readForm(exchange);
            Assert.assertNull(exchange.getRequestURI().getQuery());
            Assert.assertEquals("POST", exchange.getRequestMethod());
            Assert.assertEquals(List.of("application/x-www-form-urlencoded"),
                    exchange.getRequestHeaders().get("Content-Type"));
            Assert.assertEquals("client-id", form.get("client_id"));
            Assert.assertEquals("secret +&=中文", form.get("client_secret"));
            Assert.assertEquals("authorization-code", form.get("code"));
            Assert.assertEquals("https://client.example.com/callback", form.get("redirect_uri"));
            respond(exchange, 400, """
                    {"error":"invalid_grant","error_description":"authorization code expired"}
                    """);
        });
        server.start();
        try {
            AuthGiteaRequest request = new AuthGiteaRequest(config(serverUrl(server)));
            try {
                request.getAccessToken(callback());
                Assert.fail("Expected OAuth error");
            } catch (AuthException e) {
                Assert.assertEquals("authorization code expired", e.getMessage());
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void shouldPostMaxKeyTokenAsFormBody() throws Exception {
        HttpServer server = createServer();
        server.createContext("/sign/authz/oauth/v20/token", exchange -> {
            Map<String, String> form = readForm(exchange);
            Assert.assertNull(exchange.getRequestURI().getQuery());
            Assert.assertEquals("client-id", form.get("client_id"));
            Assert.assertEquals("secret +&=中文", form.get("client_secret"));
            respond(exchange, 200, """
                    {"access_token":"maxkey-token","token_type":"Bearer","expires_in":3600}
                    """);
        });
        server.start();
        try {
            AuthToken token = new AuthMaxKeyRequest(config(serverUrl(server))).getAccessToken(callback());
            Assert.assertEquals("maxkey-token", token.getAccessToken());
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void shouldUseBasicAndBearerHeadersForTopIam() throws Exception {
        HttpServer server = createServer();
        server.createContext("/oauth2/token", exchange -> {
            Map<String, String> form = readForm(exchange);
            Assert.assertNull(exchange.getRequestURI().getQuery());
            Assert.assertEquals("authorization-code", form.get("code"));
            Assert.assertEquals("Basic " + Base64Utils.encode("client-id:secret +&=中文".getBytes(StandardCharsets.UTF_8)),
                    exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 200, """
                    {"access_token":"topiam-token","token_type":"Bearer","expires_in":3600}
                    """);
        });
        server.createContext("/oauth2/userinfo", exchange -> {
            Assert.assertEquals("Bearer topiam-token", exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 200, """
                    {
                      "sub":"user-1",
                      "preferred_username":"aprilwind",
                      "nickname":"April Wind",
                      "picture":"https://example.com/avatar.png",
                      "email":"user@example.com"
                    }
                    """);
        });
        server.start();
        try {
            AuthTopIamRequest request = new AuthTopIamRequest(config(serverUrl(server)));
            AuthToken token = request.getAccessToken(callback());
            AuthUser user = request.getUserInfo(token);
            Assert.assertEquals("user-1", user.getUuid());
            Assert.assertEquals("aprilwind", user.getUsername());
            Assert.assertEquals("April Wind", user.getNickname());
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void shouldParseCommonTokenFields() {
        JsonNode object = JsonUtils.toNode("""
                {
                  "access_token":"access",
                  "refresh_token":"refresh",
                  "id_token":"id",
                  "token_type":"Bearer",
                  "scope":"openid profile",
                  "expires_in":3600
                }
                """);

        AuthToken token = new AuthGiteaRequest(config("https://example.com")).buildToken(object);

        Assert.assertEquals("access", token.getAccessToken());
        Assert.assertEquals("refresh", token.getRefreshToken());
        Assert.assertEquals("id", token.getIdToken());
        Assert.assertEquals("Bearer", token.getTokenType());
        Assert.assertEquals("openid profile", token.getScope());
        Assert.assertEquals(3600, token.getExpireIn());
    }


    @Test
    public void shouldMapNumericGiteaIdAndFallbackFields() throws Exception {
        HttpServer server = createServer();
        server.createContext("/login/oauth/userinfo", exchange -> {
            Assert.assertEquals("Bearer token", exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 200, "{\"id\":42,\"login\":\"april\",\"full_name\":\"April Wind\"}");
        });
        server.start();
        try {
            AuthUser user = new AuthGiteaRequest(config(serverUrl(server)))
                    .getUserInfo(AuthToken.builder().accessToken("token").build());
            Assert.assertEquals("42", user.getUuid());
            Assert.assertEquals("april", user.getUsername());
            Assert.assertEquals("April Wind", user.getNickname());
            Assert.assertTrue(user.getRawUserInfo() instanceof JsonNode);
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void shouldKeepHttpErrorsAndRejectInvalidSuccessBodies() {
        AuthGiteaRequest request = new AuthGiteaRequest(config("https://example.com"));
        Assert.assertEquals("gateway failed", Assert.assertThrows(AuthException.class,
                () -> request.parseResponse(response(false, 502, "gateway failed"))).getMessage());
        Assert.assertEquals("denied", Assert.assertThrows(AuthException.class,
                () -> request.parseResponse(response(false, 403, "{\"message\":\"denied\"}"))).getMessage());
        for (String body : Arrays.asList(null, "", "null", "[]", "bad json")) {
            Assert.assertThrows(AuthException.class, () -> request.parseResponse(response(true, 200, body)));
        }
        Assert.assertThrows(AuthException.class, () -> request.parseResponse(null));
    }


    @Test
    public void shouldUseConfiguredProxyForMaxKeyTokenAndUserInfo() throws Exception {
        HttpServer proxy = createServer();
        proxy.createContext("/sign/authz/oauth/v20/token", exchange -> {
            Map<String, String> form = readForm(exchange);
            Assert.assertEquals("secret +&=中文", form.get("client_secret"));
            respond(exchange, 200, "{\"access_token\":\"proxy-token\"}");
        });
        proxy.createContext("/sign/api/oauth/v20/me", exchange -> {
            Assert.assertEquals("Bearer proxy-token", exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 200, "{\"userId\":99,\"username\":\"april\",\"displayName\":\"April Wind\"}");
        });
        proxy.start();
        try {
            AuthConfig config = config("http://oauth.invalid");
            for (int timeout : new int[] {3000, 0, -1}) {
                config.setHttpConfig(new HttpConfig(timeout,
                        new Proxy(Proxy.Type.HTTP, proxy.getAddress())));
                AuthMaxKeyRequest request = new AuthMaxKeyRequest(config);
                AuthToken token = request.getAccessToken(callback());
                Assert.assertEquals("proxy-token", token.getAccessToken());
                AuthUser user = request.getUserInfo(token);
                Assert.assertEquals("99", user.getUuid());
                Assert.assertEquals("april", user.getUsername());
                Assert.assertEquals("April Wind", user.getNickname());
                Assert.assertEquals("MAXKEY", user.getSource());
                Assert.assertEquals(timeout, config.getHttpConfig().getTimeout());
            }
        } finally {
            proxy.stop(0);
        }
    }

    private AdapterHttpResponse response(boolean success, int code, String body) {
        return new AdapterHttpResponse(success, code, null, body, null);
    }

    private AuthConfig config(String serverUrl) {
        return AuthConfig.builder()
                .clientId("client-id")
                .clientSecret("secret +&=中文")
                .redirectUri("https://client.example.com/callback")
                .serverUrl(serverUrl)
                .build();
    }

    private AuthCallback callback() {
        AuthCallback callback = new AuthCallback();
        callback.setCode("authorization-code");
        return callback;
    }

    private HttpServer createServer() throws IOException {
        return HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    }

    private String serverUrl(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private Map<String, String> readForm(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> form = new HashMap<>();
        if (body.isEmpty()) {
            return form;
        }
        Arrays.stream(body.split("&")).forEach(item -> {
            String[] pair = item.split("=", 2);
            form.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.length == 1 ? "" : pair[1], StandardCharsets.UTF_8));
        });
        return form;
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
