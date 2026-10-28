package org.dromara.anduin;

import org.dromara.anduin.cache.AuthDefaultStateCache;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.request.AuthGithubRequest;
import org.dromara.anduin.utils.AuthStateUtils;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthClientTest {
    private static AuthConfig config() {
        return AuthConfig.builder().clientId("client").clientSecret("secret")
                .redirectUri("https://example.com/callback").build();
    }

    @Test
    void matchesSourcesIgnoringCaseAndCreatesFreshRequests() {
        AuthClient client = new AuthClient(Map.of("GiTHuB", config()));
        assertInstanceOf(AuthGithubRequest.class, client.getAuthRequest("GITHUB"));
        assertNotSame(client.getAuthRequest("github"), client.getAuthRequest("github"));
        assertTrue(client.authorize("github", "state").contains("state=state"));
    }

    @Test
    void normalizationDoesNotDependOnDefaultLocale() {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            AuthClient client = new AuthClient(Map.of("GITHUB", config()));
            assertInstanceOf(AuthGithubRequest.class, client.getAuthRequest("GITHUB"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    void rejectsInvalidConfigurationMaps() {
        assertThrows(AuthException.class, () -> new AuthClient(null));
        assertThrows(AuthException.class, () -> new AuthClient(Map.of()));
        for (String key : new String[]{null, "", " \t"}) {
            Map<String, AuthConfig> configs = new HashMap<>();
            configs.put(key, config());
            assertThrows(AuthException.class, () -> new AuthClient(configs));
        }
        Map<String, AuthConfig> configs = new HashMap<>();
        configs.put("github", null);
        assertThrows(AuthException.class, () -> new AuthClient(configs));
        assertThrows(AuthException.class, () -> new AuthClient(Map.of("github", config(), "GITHUB", config())));
    }

    @Test
    void rejectsMissingAndUnknownSourcesAndNullCallback() {
        AuthClient client = new AuthClient(Map.of("unknown", config()));
        for (String source : new String[]{null, "", " ", "github", "unknown"}) {
            assertThrows(AuthException.class, () -> client.getAuthRequest(source));
        }
        assertThrows(AuthException.class, () -> new AuthClient(Map.of("github", config())).login("github", null));
    }

    @Test
    void snapshotsMapAtBuildTime() {
        Map<String, AuthConfig> configs = new HashMap<>(Map.of("github", config()));
        AuthClient client = new AuthClient(configs);
        configs.clear();
        configs.put("gitee", config());
        assertInstanceOf(AuthGithubRequest.class, client.getAuthRequest("github"));
    }

    @Test
    void nullCacheUsesDefaultCache() {
        AuthClient client = new AuthClient(Map.of("github", config()), null);
        String state = AuthStateUtils.createState();
        try {
            client.authorize("github", state);
            assertTrue(AuthDefaultStateCache.INSTANCE.containsKey(state));
        } finally {
            AuthDefaultStateCache.INSTANCE.expire(state);
        }
    }

    @Test
    void defaultCacheConnectsAuthorizationAndLogin() throws Exception {
        try (LocalGitea provider = new LocalGitea()) {
            AuthClient client = provider.client();
            String state = AuthStateUtils.createState();
            try {
                client.authorize("gitea", state);
                assertTrue(AuthDefaultStateCache.INSTANCE.containsKey(state));
                AuthResponse<AuthUser> response = client.login("gitea", "code", state);
                assertTrue(response.ok());
                assertEquals("test", response.getData().getUsername());
                assertEquals("GITEA", response.getData().getSource());
                assertEquals("42", response.getData().getUuid());
            } finally {
                AuthDefaultStateCache.INSTANCE.expire(state);
            }
        }
    }

    @Test
    void customCacheIsUsedAcrossFreshRequestsAndRejectsInvalidState() throws Exception {
        try (LocalGitea provider = new LocalGitea()) {
            MemoryStateCache cache = new MemoryStateCache();
            AuthClient client = new AuthClient(Map.of("gitea", provider.config), cache);
            String state = AuthStateUtils.createState();
            client.authorize("gitea", state);
            assertTrue(cache.containsKey(state));
            assertFalse(AuthDefaultStateCache.INSTANCE.containsKey(state));
            assertTrue(client.login("gitea", "code", state).ok());
            assertFalse(client.login("gitea", "code", "missing").ok());
            cache.expire(state);
            assertFalse(client.login("gitea", "code", state).ok());
        }
    }

    @Test
    void preservesExplicitIgnoreStateConfiguration() throws Exception {
        try (LocalGitea provider = new LocalGitea()) {
            provider.config.setIgnoreCheckState(true);
            assertTrue(provider.client().login("gitea", "code", null).ok());
        }
    }

    @Test
    void fullCallbackPreservesCodeAndProviderFailureResponse() throws Exception {
        try (LocalGitea provider = new LocalGitea()) {
            provider.config.setIgnoreCheckState(true);
            AuthClient client = provider.client();
            AuthCallback callback = AuthCallback.builder().auth_code("special-code").build();
            assertTrue(client.login("gitea", callback).ok());
            assertTrue(provider.tokenForm.contains("code=special-code"));
            provider.tokenResponse = "{\"error\":\"invalid_grant\",\"error_description\":\"authorization code expired\"}";
            AuthResponse<AuthUser> failure = client.login("gitea", callback);
            assertFalse(failure.ok());
            assertEquals("authorization code expired", failure.getMsg());
        }
    }

    /** 使用内置 Gitea 平台和本地 HTTP 服务验证登录链路，不访问外网。 */
    private static class LocalGitea implements AutoCloseable {
        private final HttpServer server;
        private final AuthConfig config;
        private volatile String tokenForm;
        private volatile String tokenResponse = "{\"access_token\":\"token\",\"token_type\":\"bearer\"}";

        private LocalGitea() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/login/oauth/access_token", exchange -> {
                tokenForm = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                byte[] body = tokenResponse.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (var output = exchange.getResponseBody()) { output.write(body); }
                exchange.close();
            });
            server.createContext("/login/oauth/userinfo", exchange -> {
                byte[] body = "{\"id\":42,\"login\":\"test\"}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (var output = exchange.getResponseBody()) { output.write(body); }
                exchange.close();
            });
            config = config();
            config.setServerUrl("http://127.0.0.1:" + server.getAddress().getPort());
            server.start();
        }

        private AuthClient client() {
            return new AuthClient(Map.of("gitea", config));
        }

        public void close() { server.stop(0); }
    }

    private static class MemoryStateCache implements AuthStateCache {
        private final Map<String, String> entries = new HashMap<>();
        public void cache(String key, String value) { entries.put(key, value); }
        public String get(String key) { return entries.get(key); }
        public boolean containsKey(String key) { return entries.containsKey(key); }
        public void expire(String key) { entries.remove(key); }
    }

}
