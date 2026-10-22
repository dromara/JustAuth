package me.zhyd.oauth.http;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class HttpConstants {
    /**
     * 超时时长，单位毫秒
     */
    public static final int DEFAULT_TIMEOUT = 3000;

    /**
     * 编码格式
     */
    public static final Charset DEFAULT_ENCODING = StandardCharsets.UTF_8;

    /**
     * JSON
     */
    public static final String CONTENT_TYPE_JSON = "application/json; charset=utf-8";

    /**
     * Content-Type
     */
    public static final String CONTENT_TYPE = "Content-Type";

    /**
     * Content-Encoding
     */
    public static final String CONTENT_ENCODING = "Content-Encoding";

    /**
     * User-Agent
     */
    public static final String USER_AGENT = "User-Agent";

    /**
     * 模拟 User-Agent
     */
    public static final String USER_AGENT_DATA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 HttpClientAdapter";

    /**
     * 空字符串
     */
    public static final String EMPTY = "";
}
