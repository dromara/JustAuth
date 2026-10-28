package org.dromara.anduin;

import org.apache.commons.lang3.StringUtils;
import org.dromara.anduin.cache.AuthDefaultStateCache;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.request.AuthRequest;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 第三方授权登录统一门面。
 * <p>
 * 构建时复制配置 Map 的结构，但不深拷贝 AuthConfig 配置对象。
 * 请勿并发修改配置对象；配置变更时应创建新的客户端。集群部署必须提供共享的 state 缓存。
 * 本地账号绑定和应用会话管理仍由调用方负责。
 * <p>
 * 本门面仅接入 SDK 内置平台。自定义平台需实现对应请求，并使用 AuthRequestBuilder 的扩展入口。
 * 每次授权或登录均创建新的请求实例，但复用当前客户端的 state 缓存。
 *
 * @author AprilWind
 */
public final class AuthClient {
    /**
     * 平台名称到授权配置的只读映射，键已统一转为小写，配置对象本身不深拷贝。
     */
    private final Map<String, AuthConfig> configs;
    /**
     * 授权与回调共同使用的 state 缓存，用于底层请求的状态校验。
     */
    private final AuthStateCache stateCache;

    /**
     * 使用平台配置和 SDK 默认的进程内 state 缓存创建客户端。
     * <p>
     * 集群部署应使用双参数构造方法提供共享缓存。
     *
     * @param configs 平台配置，键为内置平台名称，忽略大小写；值为完整的授权配置
     * @throws AuthException 配置 Map 为空、平台名称为空白、配置值为 null，或平台名称忽略大小写后重复
     */
    public AuthClient(Map<String, AuthConfig> configs) {
        this(configs, null);
    }

    /**
     * 使用平台配置和指定的 state 缓存创建客户端。
     * <p>
     * 复制配置 Map 的结构，但不深拷贝 AuthConfig；构建后请勿并发修改配置对象。
     * 此处只校验配置映射的结构；平台是否受支持、凭据和回调地址是否合法等校验，
     * 在创建具体授权请求时由底层实现执行。
     * <p>
     * 授权与回调复用指定的缓存。集群部署需传入 Redis 等共享缓存的 AuthStateCache 实现，
     * 本 SDK 不绑定具体缓存框架。
     *
     * @param configs 平台配置，键为内置平台名称，忽略大小写；值为完整的授权配置
     * @param stateCache 共用的 state 缓存，为 null 时使用 AuthDefaultStateCache.INSTANCE
     * @throws AuthException 配置 Map 为空、平台名称为空白、配置值为 null，或平台名称忽略大小写后重复
     */
    public AuthClient(Map<String, AuthConfig> configs, AuthStateCache stateCache) {
        if (configs == null || configs.isEmpty()) {
            throw new AuthException("Platform configurations must not be empty");
        }
        Map<String, AuthConfig> snapshot = new HashMap<>();
        configs.forEach((source, config) -> {
            String key = normalizeSource(source);
            if (config == null) {
                throw new AuthException("Platform configuration must not be null: " + key);
            }
            if (snapshot.putIfAbsent(key, config) != null) {
                throw new AuthException("Duplicate platform configuration: " + key);
            }
        });
        this.configs = Map.copyOf(snapshot);
        this.stateCache = stateCache == null ? AuthDefaultStateCache.INSTANCE : stateCache;
    }

    /**
     * 使用当前客户端的配置和 state 缓存创建新的授权请求。
     * <p>
     * 平台名称匹配 SDK 内置平台的 {@link AuthDefaultSource#getName()}，不提供额外别名。
     * 每次调用均返回新的请求实例；平台配置的合法性由底层请求实现校验。
     *
     * @param source 平台名称，忽略大小写
     * @return 新的授权请求，也可用于刷新令牌和撤销授权等操作
     * @throws AuthException 平台名称为空白、平台未配置、不支持该平台，或请求构建失败
     */
    public AuthRequest getAuthRequest(String source) {
        String key = normalizeSource(source);
        AuthConfig config = configs.get(key);
        if (config == null) {
            throw new AuthException("No configuration for platform: " + key);
        }
        return AuthRequestBuilder.builder().source(key).authConfig(config)
                .authStateCache(stateCache).build();
    }

    /**
     * 调用底层平台实现生成授权地址。
     * <p>
     * state 的生成、保存及授权能力限制沿用底层平台实现。调用方应生成随机状态值，
     * 并在回调时传入平台返回的 state，不应使用固定值。
     *
     * @param source 平台名称
     * @param state  调用方生成的状态值，可通过 AuthStateUtils 生成
     * @return 授权地址
     * @throws AuthException 平台配置或请求构建失败，或底层平台不支持该授权操作
     */
    public String authorize(String source, String state) {
        return getAuthRequest(source).authorize(state);
    }

    /**
     * 委托底层请求处理完整回调，保留平台特有字段和原始响应。
     * <p>
     * 不额外捕获异常或包装响应。底层实现可能将登录失败转换为失败响应，
     * 调用方必须检查 {@link AuthResponse#ok()}，成功后再处理本地账号绑定和应用会话。
     * state 校验遵循平台实现和 AuthConfig 的配置，本门面不会关闭校验。
     *
     * @param source   平台名称
     * @param callback 完整的平台回调参数，不能为 null
     * @return 底层登录响应，调用方须检查是否登录成功
     * @throws AuthException 回调为 null、平台配置或请求构建失败；底层直接抛出的异常原样传播
     */
    public AuthResponse<AuthUser> login(String source, AuthCallback callback) {
        if (callback == null) {
            throw new AuthException("Authorization callback must not be null");
        }
        return getAuthRequest(source).login(callback);
    }

    /**
     * 普通 code/state 授权码回调的便捷入口。
     * 需要额外回调字段的平台应使用 {@link #login(String, AuthCallback)}。
     * 此方法仅组装 code 和 state，不推断或补齐平台特有字段。
     *
     * @param source 平台名称
     * @param code   授权码
     * @param state  回调状态值
     * @return 底层登录响应
     * @throws AuthException 平台配置或请求构建失败；底层直接抛出的异常原样传播
     */
    public AuthResponse<AuthUser> login(String source, String code, String state) {
        return login(source, AuthCallback.builder().code(code).state(state).build());
    }

    /**
     * 校验平台名称，并使用固定区域规则转为小写，不去除首尾空白或转换平台别名。
     *
     * @param source 原始平台名称
     * @return 小写平台名称
     * @throws AuthException 平台名称为 null、空串或纯空白
     */
    private static String normalizeSource(String source) {
        if (StringUtils.isBlank(source)) {
            throw new AuthException("Platform source must not be blank");
        }
        return source.toLowerCase(Locale.ROOT);
    }

}
