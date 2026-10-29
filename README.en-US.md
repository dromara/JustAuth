<p align="center">

</p>
<p align="center">
	<strong>Social Login, so easy.</strong>
</p>
<p align="center">
	<a target="_blank" href="https://search.maven.org/search?q=dromara-anduin">
		<img src="https://img.shields.io/github/v/release/dromara/anduin?style=flat-square" ></img>
	</a>
	<a target="_blank" href="https://www.oracle.com/technetwork/java/javase/downloads/index.html">
		<img src="https://img.shields.io/badge/JDK-17+-green.svg" ></img>
	</a>
</p>

-------------------------------------------------------------------------------

`Dromara Anduin`, as you see, It is just a Java library of third-party authorized login, It's smaller and easier to use. Anduin is the best third-party login tool written in JAVA.

Anduin is an open-source project maintained by the Dromara community, based on `yadong.zhang/JustAuth v1.16.7`, and released under the MIT License.

## Features

1. **Multiple platform**: Has integrated more than a dozen third-party platforms.([plan](https://gitee.com/dromara/anduin/issues))
2. **Minimalist**: The minimalist design is very simple to use.

## Quick start

### JDK Minimum version >= 17

### Add maven dependency

- Add Anduin dependency

These artifacts are available from Maven Central:
```xml
<dependency>
    <groupId>org.dromara.anduin</groupId>
    <artifactId>dromara-anduin</artifactId>
    <version>{latest-version}</version>
</dependency>
```

### Using Anduin API

#### Simple

```java
//1. Create authorization request
AuthRequest authRequest = new AuthGiteeRequest(AuthConfig.builder()
        .clientId("clientId")
        .clientSecret("clientSecret")
        .redirectUri("redirectUri")
        .build());

//2. Generate authorization page url
//   AuthStateUtils.createState()//create state
//   authRequest.authorize(AuthStateUtils.createState())
authRequest.authorize("your state");

//3. Get token and userinfo
AuthCallback callback = AuthCallback.builder()
        .code("code")
        .state("state")
        .build();
authRequest.login(callback);
```

#### Builder 1. Use unchanging `AuthConfig`

```java
// Create authorization request
AuthRequest authRequest = AuthRequestBuilder.builder()
    .source("github")
    .authConfig(AuthConfig.builder()
        .clientId("clientId")
        .clientSecret("clientSecret")
        .redirectUri("redirectUri")
        .build())
    .build();
```

#### Builder 2. Use dynamic `AuthConfig`

```java
// Create authorization request
AuthRequest authRequest = AuthRequestBuilder.builder()
    .source("gitee")
    .authConfig((source) -> {
        // Use source to dynamically get AuthConfig
        // Here you can flexibly take the configuration from sql or take the configuration from the configuration file
        return AuthConfig.builder()
            .clientId("clientId")
            .clientSecret("clientSecret")
            .redirectUri("redirectUri")
            .build();
    })
    .build();
```

#### Builder 3. Support custom platform

```java
AuthRequest authRequest = AuthRequestBuilder.builder()
    // Key point: configure the custom implementation of AuthSource
    .extendSource(AuthExtendSource.values())
    // Enum name in AuthExtendSource
    .source("other")
    // ... Do other things
    .build();
```

### Unified AuthClient Facade

`AuthClient` requires no Spring dependency. Configure it once and reuse it for authorization and callbacks. Spring applications can register it as a bean themselves.

```java
import java.util.Map;
import org.dromara.anduin.AuthClient;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthStateUtils;

Map<String, AuthConfig> configs = Map.of("gitee", AuthConfig.builder()
        .clientId("clientId")
        .clientSecret("clientSecret")
        .redirectUri("https://example.com/oauth/callback")
        .build());

AuthClient client = new AuthClient(configs);
// For clustered deployments, supply a shared AuthStateCache implementation:
// AuthClient client = new AuthClient(configs, sharedStateCache);

// Authorization endpoint: redirect the browser to this URL
String url = client.authorize("gitee", AuthStateUtils.createState());

// Callback endpoint: use the actual code and state returned by the provider
AuthResponse<AuthUser> response = client.login("gitee", code, state);
if (!response.ok()) {
    throw new IllegalStateException(response.getMsg());
}
AuthUser authUser = response.getData();
// Look up the local account binding using authUser.getSource() and authUser.getUuid(),
// validate the local account, then create an application session or issue a token.
```

- For provider-specific callbacks, bind all fields to `AuthCallback` and call `client.login(source, callback)`. Preserve fields such as Twitter's `oauth_token` / `oauth_verifier` and Apple's `user`. The code/state overload is only for ordinary authorization-code callbacks.
- Use `client.getAuthRequest(source)` for underlying refresh, revoke, and other operations. Each operation creates a fresh request rather than caching request objects.
- The default state cache is the SDK's in-process cache. Clustered deployments must supply a shared cache through the two-argument constructor, used by both authorization and callbacks. The facade does not disable or override existing state-validation settings.
- The facade supports SDK built-in platforms only; custom platforms require a request implementation and the underlying `AuthRequestBuilder` extension API. Platform names are case-insensitive and follow `AuthRequestBuilder`; no RuoYi aliases are added. Configuration keys differing only in case are rejected.
- Building a client snapshots the map structure, not the mutable `AuthConfig` values. Do not mutate configuration objects concurrently; create a new client when changing configuration.
- Third-party authentication does not complete local application login. Account bindings, account status checks, and sessions remain application responsibilities. Existing Builder and direct `AuthRequest` usage remain unchanged.

### Capabilities, Dependencies, And Deployment

- [Full built-in capability table and integration guide](docs/integration.md): authorize/login/refresh/revoke implementations for every built-in key, inherited method tracing, special configuration, and source support versus offline tests versus real-provider verification.
- Commons Lang, Commons Collections, Guava, Jackson 3, and Caffeine are transitive core dependencies. Alipay SDK and Apple's JJWT/Bouncy Castle dependencies are provider-specific and must be declared explicitly by consumers; the guide includes Maven XML and current versions.
- The default shared in-process state cache expires entries **5 minutes after write**; it is not shared across nodes. Clustered deployments must inject an `AuthStateCache` implementation through the two-argument constructor. The guide includes framework-neutral Redis pseudocode, TTL and logging constraints, and the existing non-atomic state-validation semantics.
- Review current AFDIAN mapping, QQ mini-program Builder entry, and Apple configuration-lifecycle limitations before use. An implemented method is not proof of successful real-provider integration.

## Contributions

1. Fork this project to your repository
2. Clone the project after fork.
3. Modify the code (either to fix issue, or to add new features)
4. Commit and push code to a remote repository
5. Create a new PR (pull request), and select `dev` branch
6. Waiting for author to merge

I look forward to your joining us.

## Change Logs

[CHANGELOGS](https://gitee.com/dromara/anduin/blob/master/CHANGELOGS.md)

## References

- [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0](https://oauth.net/2/)
