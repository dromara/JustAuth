package org.dromara.anduin;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.config.AuthSource;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.request.AuthDefaultRequest;
import org.dromara.anduin.request.AuthRequest;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.function.Function;

/**
 * 快捷的构建 AuthRequest
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @author ngcly
 * @version 1.0.0
 * @since 1.16.3
 */
public class AuthRequestBuilder {
    private String source;
    private AuthConfig authConfig;
    private AuthStateCache authStateCache;
    private AuthSource[] extendSource;

    private AuthRequestBuilder() {

    }

    public static AuthRequestBuilder builder() {
        return new AuthRequestBuilder();
    }

    public AuthRequestBuilder source(String source) {
        this.source = source;
        return this;
    }

    public AuthRequestBuilder authConfig(AuthConfig authConfig) {
        this.authConfig = authConfig;
        return this;
    }

    public AuthRequestBuilder authConfig(Function<String, AuthConfig> authConfig) {
        this.authConfig = authConfig.apply(this.source);
        return this;
    }

    public AuthRequestBuilder authStateCache(AuthStateCache authStateCache) {
        this.authStateCache = authStateCache;
        return this;
    }

    public AuthRequestBuilder extendSource(AuthSource... extendSource) {
        this.extendSource = extendSource;
        return this;
    }

    public AuthRequest build() {
        if (StringUtils.isEmpty(this.source) || null == this.authConfig) {
            throw new AuthException(AuthResponseStatus.NOT_IMPLEMENTED);
        }
        // 合并 JustAuth 默认的 AuthDefaultSource 和 开发者自定义的 AuthSource
        AuthSource[] sources = this.concat(AuthDefaultSource.values(), extendSource);
        // 筛选符合条件的 AuthSource
        AuthSource source = Arrays.stream(sources).distinct()
                .filter(authSource -> authSource.getName().equalsIgnoreCase(this.source))
                .findAny()
                .orElseThrow(() -> new AuthException(AuthResponseStatus.NOT_IMPLEMENTED));

        Class<? extends AuthDefaultRequest> targetClass = source.getTargetClass();
        if (null == targetClass) {
            throw new AuthException(AuthResponseStatus.NOT_IMPLEMENTED);
        }
        try {
            if (this.authStateCache == null) {
                return targetClass.getDeclaredConstructor(AuthConfig.class).newInstance(this.authConfig);
            } else {
                return targetClass.getDeclaredConstructor(AuthConfig.class, AuthStateCache.class).newInstance(this.authConfig, this.authStateCache);
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new AuthException(AuthResponseStatus.NOT_IMPLEMENTED);
        }
    }

    private AuthSource[] concat(AuthSource[] first, AuthSource[] second) {
        if (null == second || second.length == 0) {
            return first;
        }
        AuthSource[] result = new AuthSource[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

}
