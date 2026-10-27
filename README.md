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

## Dromara Anduin

Anduin，如你所见，它仅仅是一个**第三方授权登录**的**工具类库**，它可以让我们脱离繁琐的第三方登录 SDK，让登录变得**So easy!**

Anduin 集成了诸如：Github、Gitee、支付宝、新浪微博、微信、Google、Facebook、Twitter、StackOverflow等国内外数十家第三方平台。

Dromara Anduin 是Dromara开源社区维护的开源项目，基于`yadong.zhang/JustAuth v1.16.7`，MIT 协议


## 特点

- 集成国内外数十家第三方平台，实现快速接入。
- 自定义 State 缓存，支持各种分布式缓存组件。
- 自定义 OAuth 平台，更容易适配自有的 OAuth 服务。
- 自定义 Http 实现，选择权完全交给开发者，不会单独依赖某一具体实现。
- 自定义 Scope，支持更完善的授权体系。
- 持续扩展中（[开发计划](https://gitee.com/dromara/anduin/issues)）。

## 快速开始

### JDK 版本要求 >= 17

### 引入依赖
```xml
<dependency>
    <groupId>org.dromara.anduin</groupId>
    <artifactId>dromara-anduin</artifactId>
    <version>{latest-version}</version>
</dependency>
```

### 使用JustAuth API

#### 普通方式

```java
//1. 创建授权request
AuthRequest authRequest = new AuthGiteeRequest(AuthConfig.builder()
        .clientId("clientId")
        .clientSecret("clientSecret")
        .redirectUri("redirectUri")
        .build());

//2. 生成登录授权URL
//   生成state
//   AuthStateUtils.createState()
//   authRequest.authorize(AuthStateUtils.createState())
authRequest.authorize("your state");

//3. 授权登录回调
// 授权登录后会返回code（auth_code（仅限支付宝））、state，1.8.0版本后，可以用AuthCallback类作为回调接口的参数
// 注：JustAuth默认保存state的时效为3分钟，3分钟内未使用则会自动清除过期的state
AuthCallback callback = AuthCallback.builder()
        .code("code")
        .state("state")
        .build();
        
authRequest.login(callback);
```

#### AuthRequest Builder 方式一

静态配置 `AuthConfig`

```java
//创建授权request
AuthRequest authRequest = AuthRequestBuilder.builder()
    .source("github")
    .authConfig(AuthConfig.builder()
        .clientId("clientId")
        .clientSecret("clientSecret")
        .redirectUri("redirectUri")
        .build())
    .build();
```

#### AuthRequest Builder 方式二

动态获取并配置 `AuthConfig`

```java
//创建授权request
AuthRequest authRequest = AuthRequestBuilder.builder()
    .source("gitee")
    .authConfig((source) -> {
        // 通过 source 动态获取 AuthConfig
        // 此处可以灵活的从 sql 中取配置也可以从配置文件中取配置
        return AuthConfig.builder()
            .clientId("clientId")
            .clientSecret("clientSecret")
            .redirectUri("redirectUri")
            .build();
    })
    .build();
```

#### AuthRequest Builder 方式支持自定义的平台

```java
//创建授权request
AuthRequest authRequest = AuthRequestBuilder.builder()
    // 关键点：将自定义实现的 AuthSource 配置上
    .extendSource(AuthExtendSource.values())
    // source 对应 AuthExtendSource 中的枚举 name
    .source("other")
    // ... 其他内容不变，参考上面的示例
    .build();
```

## 更新日志

- [CHANGELOGS](https://gitee.com/dromara/anduin/blob/master/CHANGELOGS.md)
