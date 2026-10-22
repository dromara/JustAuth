package me.zhyd.oauth.cache;

import java.time.Duration;

import org.apache.commons.lang3.StringUtils;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * 默认的缓存实现
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.9.3
 */
public class AuthDefaultCache implements AuthCache {

    /**
     * state cache
     */
    private static Cache<String, String> stateCache = null;

    public AuthDefaultCache() {
    		stateCache = Caffeine.newBuilder()
    				.maximumSize(10_000)
    				.expireAfterWrite(Duration.ofMinutes(AuthCacheConfig.timeout))
    				.build();
    }

    /**
     * 设置缓存
     *
     * @param key   缓存KEY
     * @param value 缓存内容
     */
    @Override
    public void set(String key, String value) {
    		stateCache.put(key, value);
    }

    /**
     * 获取缓存
     *
     * @param key 缓存KEY
     * @return 缓存内容
     */
    @Override
    public String get(String key) {
    		return stateCache.getIfPresent(key);
    }

    /**
     * 是否存在key，如果对应key的value值已过期，也返回false
     *
     * @param key 缓存KEY
     * @return true：存在key，并且value没过期；false：key不存在或者已过期
     */
    @Override
    public boolean containsKey(String key) {
    		String value = stateCache.getIfPresent(key);
    		return StringUtils.isNotBlank(value);
    }

    /**
     * Discards any cached value for the key
     */
	@Override
	public void expire(String key) {
		stateCache.invalidate(key);
	}

}
