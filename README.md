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

### 使用 Anduin API

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
// 注：Anduin 默认 state 缓存写入后 5 分钟过期；校验不等于原子消费，详见集成说明
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

### 使用 AuthClient 统一门面

`AuthClient` 无需 Spring 等框架依赖。初始化一次后，统一按平台名生成授权地址和处理登录回调；Spring 项目也可以自行将其注册为 Bean。

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
// 集群部署时传入实现 AuthStateCache 的共享缓存：
// AuthClient client = new AuthClient(configs, sharedStateCache);

// 授权入口：将浏览器重定向到此 URL
String url = client.authorize("gitee", AuthStateUtils.createState());

// 回调入口：使用平台实际返回的 code、state
AuthResponse<AuthUser> response = client.login("gitee", code, state);
if (!response.ok()) {
    throw new IllegalStateException(response.getMsg());
}
AuthUser authUser = response.getData();
// 业务方根据 authUser.getSource() 和 authUser.getUuid() 查询本地账号绑定，
// 校验本地账号状态后，再创建应用会话或签发 token。
```

- 特殊平台回调应完整绑定到 `AuthCallback`，再调用 `client.login(source, callback)`；不要丢弃 Twitter 的 `oauth_token` / `oauth_verifier`、Apple 的 `user` 等字段。`code/state` 重载仅适用于普通授权码回调。
- 使用 `client.getAuthRequest(source)` 可访问底层刷新 token、撤销授权等能力。每次调用创建新的请求实例，不缓存请求对象。
- 未配置缓存时沿用 SDK 的进程内 state 缓存；集群部署必须通过双参数构造方法提供共享缓存，授权和回调使用同一缓存。门面不会关闭或覆盖现有 state 校验配置。
- 门面仅支持 SDK 内置平台；自定义平台需实现对应请求并使用底层 `AuthRequestBuilder` 扩展入口。平台名忽略大小写，遵循现有 `AuthRequestBuilder` 的平台名称，不提供若依平台别名；重复的大小写配置键会被拒绝。
- 构建时复制配置 Map 的结构，但不深拷贝 `AuthConfig`。构建后不要并发修改配置对象；配置变更时创建新的客户端。
- 第三方认证成功不等于本地账号登录完成；本地绑定、账号状态及应用会话由业务方负责。原有 Builder 和直接使用 `AuthRequest` 的方式不受影响。

### 平台能力、依赖与部署说明

- [完整内置平台能力表与集成指南](docs/integration.md)：逐个平台列出授权、登录、刷新、撤销实现，追溯继承方法，并区分源码支持、离线测试与真实平台验证。
- Commons Lang、Commons Collections、Guava、Jackson 3 和 Caffeine 作为核心依赖传递引入；支付宝 SDK、Apple 的 JJWT/Bouncy Castle 为可选平台依赖，使用相应平台前按指南在消费方显式声明。
- 默认缓存为进程内共享缓存，写入后 **5 分钟**过期，不支持跨节点共享。集群需实现 `AuthStateCache` 并注入双参数构造方法；指南提供不依赖框架的 Redis 命令伪代码和 TTL、日志及 state 非原子消费约束。
- 注意当前 AFDIAN 映射、QQ 小程序 Builder 入口、Apple 配置生命周期等限制；不能将“有实现”理解为“已完成真实平台联调”。

## 更新日志

- [CHANGELOGS](https://gitee.com/dromara/anduin/blob/master/CHANGELOGS.md)
