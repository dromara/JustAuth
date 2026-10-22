<p align="center">
	<img src="https://gitee.com/yadong.zhang/static/raw/master/JustAuth/Justauth.png" width="200">
</p>
<p align="center">
	<strong>Social Login, so easy.</strong>
</p>
<p align="center">
	<a target="_blank" href="https://search.maven.org/search?q=JustAuth">
		<img src="https://img.shields.io/github/v/release/justauth/JustAuth?style=flat-square" ></img>
	</a>
	<a target="_blank" href="https://www.oracle.com/technetwork/java/javase/downloads/index.html">
		<img src="https://img.shields.io/badge/JDK-17+-green.svg" ></img>
	</a>
	<a href='https://gitee.com/yadong.zhang/JustAuth/stargazers'>
	  <img src='https://gitee.com/yadong.zhang/JustAuth/badge/star.svg?theme=gvp' alt='star'></img>
	</a>
	<a target="_blank" href='https://github.com/zhangyd-c/JustAuth'>
		<img src="https://img.shields.io/github/stars/zhangyd-c/JustAuth.svg?style=social" alt="github star"></img>
	</a>
</p>

-------------------------------------------------------------------------------

`Dromara JustAuth`, as you see, It is just a Java library of third-party authorized login, It's smaller and easier to use. JustAuth is the best third-party login tool written in JAVA.

JustAuth is an open-source project maintained by the Dromara community, based on `yadong.zhang/JustAuth v1.16.7`, and released under the MIT License.

## Features

1. **Multiple platform**: Has integrated more than a dozen third-party platforms.([plan](https://gitee.com/dromara/JustAuth/issues))
2. **Minimalist**: The minimalist design is very simple to use.

## Quick start

### JDK Minimum version >= 17

### Add maven dependency

- Add JustAuth dependency

These artifacts are available from Maven Central:
```xml
<dependency>
    <groupId>org.dromara.justauth</groupId>
    <artifactId>JustAuth</artifactId>
    <version>{latest-version}</version>
</dependency>
```

### Using JustAuth API

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

## Contributions

1. Fork this project to your repository
2. Clone the project after fork.
3. Modify the code (either to fix issue, or to add new features)
4. Commit and push code to a remote repository
5. Create a new PR (pull request), and select `dev` branch
6. Waiting for author to merge

I look forward to your joining us.


## Change Logs

[CHANGELOGS](https://gitee.com/dromara/JustAuth/blob/master/CHANGELOGS.md)

## References

- [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0](https://oauth.net/2/)
