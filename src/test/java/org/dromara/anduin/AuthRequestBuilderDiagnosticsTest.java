package org.dromara.anduin;

import org.dromara.anduin.cache.AuthDefaultStateCache;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthSource;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.request.AuthDefaultRequest;
import org.dromara.anduin.request.AuthGithubRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuthRequestBuilderDiagnosticsTest {
    private static final AuthException VALIDATION = new AuthException(5015, "Invalid client secret");
    private static final IllegalStateException CONSTRUCTION = new IllegalStateException("secret-fixture");

    @Test
    void preservesValidationExceptionWithEitherConstructor() {
        for (boolean customCache : new boolean[]{false, true}) {
            AuthRequestBuilder builder = builder(ValidationRequest.class);
            if (customCache) {
                builder.authStateCache(AuthDefaultStateCache.INSTANCE);
            }
            assertSame(VALIDATION, assertThrows(AuthException.class, builder::build));
        }
    }

    @Test
    void preservesReflectionFailureWithoutLeakingCauseMessage() {
        AuthException failure = assertThrows(AuthException.class, builder(BrokenRequest.class)::build);
        assertEquals(5000, failure.getErrorCode());
        assertSame(CONSTRUCTION, failure.getCause());
        assertFalse(failure.getMessage().contains("secret-fixture"));
        assertTrue(failure.getMessage().contains("CUSTOM"));
        assertTrue(failure.getMessage().contains(BrokenRequest.class.getName()));
    }

    @Test
    void missingConstructorIsFailureNotUnsupportedSource() {
        AuthException failure = assertThrows(AuthException.class, builder(MissingConstructorRequest.class)::build);
        assertEquals(5000, failure.getErrorCode());
        assertInstanceOf(NoSuchMethodException.class, failure.getCause());
    }

    @Test
    void linkageFailureRetainsCause() {
        AuthException failure = assertThrows(AuthException.class, builder(LinkageRequest.class)::build);
        assertEquals(5000, failure.getErrorCode());
        assertInstanceOf(NoClassDefFoundError.class, failure.getCause());
    }

    @Test
    void staticInitializerLinkageFailureRetainsCause() {
        AuthException failure = assertThrows(AuthException.class, builder(InitializationFailureRequest.class)::build);
        assertEquals(5000, failure.getErrorCode());
        assertInstanceOf(NoClassDefFoundError.class, failure.getCause());
        assertFalse(failure.getMessage().contains("secret-fixture"));
    }

    @Test
    void unsupportedInputsKeepStatusAndSafeContext() {
        AuthException missing = assertThrows(AuthException.class, () -> AuthRequestBuilder.builder().build());
        assertEquals(5001, missing.getErrorCode());
        assertTrue(missing.getMessage().contains("source"));
        AuthException unknown = assertThrows(AuthException.class, () -> AuthRequestBuilder.builder()
                .source("unknown").authConfig(config()).build());
        assertEquals(5001, unknown.getErrorCode());
        assertTrue(unknown.getMessage().contains("unknown"));
        AuthException noTarget = assertThrows(AuthException.class, builder(null)::build);
        assertEquals(5001, noTarget.getErrorCode());
        assertTrue(noTarget.getMessage().contains("CUSTOM"));
    }

    @Test
    void causeConstructorsPopulateFailureMetadata() {
        AuthException explicit = new AuthException("diagnostic", CONSTRUCTION);
        assertEquals(AuthResponseStatus.FAILURE.getCode(), explicit.getErrorCode());
        assertEquals("diagnostic", explicit.getErrorMsg());
        assertSame(CONSTRUCTION, explicit.getCause());
        AuthException implicit = new AuthException(CONSTRUCTION);
        assertEquals(5000, implicit.getErrorCode());
        assertEquals(implicit.getMessage(), implicit.getErrorMsg());
        assertSame(CONSTRUCTION, implicit.getCause());
    }

    private static AuthConfig config() {
        return AuthConfig.builder().clientId("id").clientSecret("secret-fixture")
                .redirectUri("https://example.com/callback").build();
    }

    private static AuthRequestBuilder builder(Class<? extends AuthDefaultRequest> type) {
        AuthSource source = new AuthSource() {
            public String authorize() { return "https://example.com"; }
            public String accessToken() { return "https://example.com"; }
            public String userInfo() { return "https://example.com"; }
            public String getName() { return "CUSTOM"; }
            public Class<? extends AuthDefaultRequest> getTargetClass() { return type; }
        };
        return AuthRequestBuilder.builder().source("CUSTOM").extendSource(source).authConfig(config());
    }

    public static class ValidationRequest extends AuthGithubRequest {
        public ValidationRequest(AuthConfig config) { super(config); throw VALIDATION; }
        public ValidationRequest(AuthConfig config, AuthStateCache cache) { super(config, cache); throw VALIDATION; }
    }

    public static class BrokenRequest extends AuthGithubRequest {
        public BrokenRequest(AuthConfig config) { super(config); throw CONSTRUCTION; }
    }

    public static class MissingConstructorRequest extends AuthGithubRequest {
        public MissingConstructorRequest(AuthConfig config, String ignored) { super(config); }
    }

    public static class LinkageRequest extends AuthGithubRequest {
        public LinkageRequest(AuthConfig config) { super(config); throw new NoClassDefFoundError("secret-fixture"); }
    }

    public static class InitializationFailureRequest extends AuthGithubRequest {
        static {
            failInitialization();
        }
        public InitializationFailureRequest(AuthConfig config) { super(config); }

        private static void failInitialization() {
            throw new NoClassDefFoundError("secret-fixture");
        }
    }
}
