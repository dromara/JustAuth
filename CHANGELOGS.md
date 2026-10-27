## 2.2.0
- 提取授权码模式获取 Token 参数定义通用方法，去除大量重复代码
- 提取验证响应通用方法，去除大量重复代码
- jjwt-jackson 替换为 jjwt-gson，消息对 jackson2 版本的依赖
- JsonUtils 改用内容 Log 输出，去除对 slf4j 的依赖
- 删除无用的代码和文件

## 2.1.0 2026/10/25
- JDK升级至17
- 优化 pom 配置 2. 改用 fastjson2 替换原有 fastjson 3. 升级依赖组件和 Maven 组件版本
- 定义常量类替换原有部分大量重复出现的字符串
- 升级 Github Action 插件版本
- http 默认使用jdk java.net.http.HttpClient
- 去除 fastjson2 依赖，主要 json 处理修改为 jackson3
- 统一变量命名和 Builder 类方法调用顺序，便于 IDEA 分析重复代码生成重构提示
- 将重复率较高的魔法值提取为常量，便于代码维护
- 修复单元测试代码异常
- 简化 pom 配置 2. 去除错误的版本依赖关系
- 替换部分魔法值
- use caffeine as AuthDefaultCache
- UrlBuilder mv to me.zhyd.oauth.http
- fix 修复企业微信登录新旧版userId获取
- fix 修复新版钉钉二维码登录
- add 新增私有化部署，支持Gitea,MaxKey,TopIAM
- 将低版本 JUnit 单元测试代码适配至新版本代码
- 更新README
- 依赖升级
  - lombok 版本升级至 1.18.48
  - maven-surefire-plugin 版本升级至 3.6.0
  - maven-compiler-plugin 版本升级至 3.16.0
  - maven-compiler-plugin 版本升级至 3.16.0
  - Junit 版本升级至 6.x
  - alipay-sdk-java  4.40.1044.ALL
  - bcpkix-jdk18on  1.86
  - bcprov-jdk18on  1.86
  - commons-collections4  4.6.0
  - commons-lang3  3.21.0
  - guava  33.7.2-jre
  - caffeine  3.3.1
  - jackson  3.2.4
  - jjwt  0.13.0
  - junit  6.1.3
  - lombok  1.18.48
  - slf4j  2.0.20

## 1.16.7 2024/12/14 yadong.zhang/JustAuth

- 新增
  - 添加`微信小程序`登录能力，对接文档：[点击查看](https://justauth.cn/guide/oauth/wechat_mini_program/)。
  - 添加`支付宝证书模式`登录能力（原支持的公钥登录模式依然可用），对接文档：[点击查看](https://justauth.cn/guide/oauth/alipay_cert)。
  - 添加`appleid`社交登录能力，对接文档：[点击查看](https://justauth.cn/guide/oauth/appleid/)。 [Github#192](https://github.com/justauth/JustAuth/pull/192)
  - 添加`QQ小程序`社交登录能力。 [Github#223](https://github.com/justauth/JustAuth/pull/223)
  - 添加`figma`社交登录能力。 [Gitee#41](https://gitee.com/yadong.zhang/JustAuth/pulls/41)
  - 添加新版`企业微信扫码`登录能力，对接文档：[点击查看](https://justauth.cn/guide/oauth/wechat_enterprise_qrcode_v2/)。 [Github Issue#165](https://github.com/justauth/JustAuth/issues/165)
  - 添加新版`钉钉扫码`登录能力，对接文档：[点击查看](https://justauth.cn/guide/oauth/dingtalk_v2/)。 [Gitee Issue#I73FZL](https://gitee.com/yadong.zhang/JustAuth/issues/I73FZL)
  - 添加新版`华为`登录能力，对接文档：[点击查看](https://justauth.cn/guide/oauth/huawei_v3/)，原`AuthHuaweiRequest`会在后面版本被弃用，如有使用，请切换到`AuthHuaweiV3Request`
- 优化
  - 修复文档错误。[Github #222](https://github.com/justauth/JustAuth/pull/222)
  - 更新 Google 端点地址。[Github #198](https://github.com/justauth/JustAuth/pull/198)
  - Amazon PKCE 中的 `code_verifier` 基于 `state` 缓存
  - `AuthRequest`响应时携带泛型，避免二次解析。[Gitee#38](https://gitee.com/yadong.zhang/JustAuth/pulls/38)
  - 优化业务调用方式：`getAccessToken`和`getUserInfo`两个方法从`AuthDefaultRequest`提升至`AuthRequest`中，部分场景下可以减少一次网络请求。[Github Issue#194](https://github.com/justauth/JustAuth/issues/194)
    - ***注意：如果有基于 JustAuth 规范自定义实现的三方平台 Request（[自定义第三方平台的OAuth](https://justauth.cn/features/customize-the-oauth/)），需要注意`getAccessToken`和`getUserInfo`接口的访问级别是否正确！！！***
- 其他
  -  补充单侧，[Gitee#39](https://gitee.com/yadong.zhang/JustAuth/pulls/39)

## fork版本 [yadong.zhang/JustAuth/CHANGELOGS](https://gitee.com/yadong.zhang/JustAuth/blob/master/CHANGELOGS.md)