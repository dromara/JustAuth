package org.dromara.anduin.http;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.dromara.anduin.utils.MapUtil;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <p> 构造URL </p>
 *
 * @author yangkai.shen (<a href="https://xkcoding.com">...</a>)
 * @since 1.9.0
 */
public class UrlBuilder {

    private final Map<String, String> params = new LinkedHashMap<>(7);
    private final String baseUrl;

    public UrlBuilder(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * 构造函数
     *
     * @param baseUrl 基础路径
     * @return the new {@code UrlBuilder}
     */
    public static UrlBuilder fromBaseUrl(String baseUrl) {
        return new UrlBuilder(baseUrl);
    }

    /**
     * 只读的参数Map
     *
     * @return unmodifiable Map
     * @since 1.15.0
     */
    public Map<String, Object> getReadOnlyParams() {
        return Collections.unmodifiableMap(params);
    }

    /**
     * 添加参数
     *
     * @param key   参数名称
     * @param value 参数值
     * @return this UrlBuilder
     */
    public UrlBuilder queryParam(String key, Object value) {
        if (StringUtils.isEmpty(key)) {
            throw new RuntimeException("参数名不能为空");
        }
        String valueAsString = (value != null ? value.toString() : null);
        this.params.put(key, valueAsString);

        return this;
    }

    /**
     * 添加参数
     *
     * @param params 参数 Map
     * @return this UrlBuilder
     */
    public UrlBuilder queryParams(Map<String, String> params) {
        if (MapUtils.isEmpty(params)) {
            throw new RuntimeException("参数名不能为空");
        }
        this.params.putAll(params);

        return this;
    }

    /**
     * 构造url
     *
     * @return url
     */
    public String build() {
        return this.build(false);
    }

    /**
     * 构造url
     *
     * @param encode 转码
     * @return url
     */
    public String build(boolean encode) {
        if (ObjectUtils.isEmpty(this.params)) {
            return this.baseUrl;
        }

        String baseUrl = Strings.CS.appendIfMissing(this.baseUrl, "?", "&");
        String paramString = MapUtil.parseMapToString(this.params, encode);
        return baseUrl + paramString;
    }
}
