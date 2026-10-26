package org.dromara.anduin.http;

import java.net.URLEncoder;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 可替换的统一 HTTP 请求适配器。
 *
 * @author AprilWind
 */
public interface HttpClientAdapter {
    /**
     * 以 UTF-8 表单正文发送 POST，请求参数不会追加到 URL。
     *
     * @param url    请求地址
     * @param params 表单字段
     * @param header 附加请求头
     * @return HTTP 响应
     */
    default AdapterHttpResponse postForm(String url, Map<String, String> params, HttpHeader header) {
        String body = params == null ? "" : params.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), HttpConstants.DEFAULT_ENCODING) + "="
                        + URLEncoder.encode(entry.getValue() == null ? "" : entry.getValue(),
                        HttpConstants.DEFAULT_ENCODING))
                .collect(Collectors.joining("&"));
        HttpHeader formHeader = new HttpHeader();
        if (header != null) {
            header.getHeaders().forEach((key, value) -> {
                if (!HttpConstants.CONTENT_TYPE.equalsIgnoreCase(key)) {
                    formHeader.add(key, value);
                }
            });
        }
        formHeader.add(HttpConstants.CONTENT_TYPE, "application/x-www-form-urlencoded");
        return post(url, body, formHeader);
    }

    /**
     * GET 请求
     *
     * @param url URL
     * @return 结果
     */
    public AdapterHttpResponse get(String url);

    /**
     * GET 请求
     *
     * @param url    URL
     * @param params 参数
     * @param encode 是否需要 url encode
     * @return 结果
     */
    public AdapterHttpResponse get(String url, Map<String, String> params, boolean encode);

    /**
     * GET 请求
     *
     * @param url    URL
     * @param params 参数
     * @param header 请求头
     * @param encode 是否需要 url encode
     * @return 结果
     */
    public AdapterHttpResponse get(String url, Map<String, String> params, HttpHeader header, boolean encode);

    /**
     * POST 请求
     *
     * @param url URL
     * @return 结果
     */
    public AdapterHttpResponse post(String url);

    /**
     * POST 请求
     *
     * @param url  URL
     * @param data JSON 参数
     * @return 结果
     */
    public AdapterHttpResponse post(String url, String data);

    /**
     * POST 请求
     *
     * @param url    URL
     * @param data   JSON 参数
     * @param header 请求头
     * @return 结果
     */
    public AdapterHttpResponse post(String url, String data, HttpHeader header);

    /**
     * POST 请求
     *
     * @param url    URL
     * @param params form 参数
     * @param encode 是否需要 url encode
     * @return 结果
     */
    public AdapterHttpResponse post(String url, Map<String, String> params, boolean encode);

    /**
     * POST 请求
     *
     * @param url    URL
     * @param params form 参数
     * @param header 请求头
     * @param encode 是否需要 url encode
     * @return 结果
     */
    public AdapterHttpResponse post(String url, Map<String, String> params, HttpHeader header, boolean encode);
}
