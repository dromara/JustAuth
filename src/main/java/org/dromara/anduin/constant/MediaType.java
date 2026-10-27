package org.dromara.anduin.constant;

/**
 * <p>Description: 请求头常量 </p>
 *
 * @author : gengwei.zheng
 * @date : 2025/9/11 11:32
 */
public interface MediaType {

    String SUFFIX_CHARSET_UTF8 = ";charset=utf-8";

    String APPLICATION_JSON = "application/json";
    String APPLICATION_JSON_UTF8 = APPLICATION_JSON + SUFFIX_CHARSET_UTF8;

    String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
    String APPLICATION_FORM_URLENCODED_UTF8 = APPLICATION_FORM_URLENCODED + SUFFIX_CHARSET_UTF8;
}
