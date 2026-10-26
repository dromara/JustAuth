package org.dromara.anduin.cache;

/**
 * AuthCache配置类
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.10.0
 */
public class AuthCacheConfig {

    /**
     * 默认缓存过期时间：5分钟
     * 鉴于授权过程中，根据个人的操作习惯，或者授权平台的不同（google等），每个授权流程的耗时也有差异，不过单个授权流程一般不会太长
     */
    public static long timeout = 5;
}
