package me.zhyd.oauth.http.adapter;

import me.zhyd.oauth.exception.AuthHttpException;
import me.zhyd.oauth.http.*;
import me.zhyd.oauth.utils.MapUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 使用 JDK HTTP 客户端发送请求。
 *
 * @author AprilWind
 */
public class JdkHttpAdapter implements HttpClientAdapter {
    HttpConfig httpConfig;
    private final HttpClient.Builder clientBuilder;

    public JdkHttpAdapter() {
        this(new HttpConfig());
    }

    public JdkHttpAdapter(HttpConfig httpConfig) {
        this(HttpClient.newBuilder(), httpConfig);
    }

    public JdkHttpAdapter(HttpClient.Builder clientBuilder, HttpConfig httpConfig) {
        this.httpConfig = httpConfig;
        this.clientBuilder = clientBuilder;
    }

    private AdapterHttpResponse execute(HttpRequest.Builder builder) {
        this.addHeader(builder);
        try {
            HttpClient client;

            if (null != httpConfig.getProxy()) {
                client = clientBuilder.connectTimeout(Duration.ofMillis(httpConfig.getTimeout())).proxy(new JdkHttpProxySelector(httpConfig)).build();
            } else {
                client = clientBuilder.connectTimeout(Duration.ofMillis(httpConfig.getTimeout())).build();
            }

            HttpRequest request = builder.build();
            HttpResponse<String> httpResponse = client.send(request, HttpResponse.BodyHandlers.ofString());

            int code = httpResponse.statusCode();
            boolean successful = isSuccess(httpResponse);
            Map<String, List<String>> headers = httpResponse.headers().map();
            String body = httpResponse.body();
            return new AdapterHttpResponse(successful, code, headers, body, null);
        } catch (Exception e) {
            e.printStackTrace();
            return new AdapterHttpResponse(false, 500, null, null, e.getMessage());
        }
    }

    private boolean isSuccess(HttpResponse<String> response) {
        if (response == null) {
            return false;
        }
        return response.statusCode() >= 200 && response.statusCode() < 300;
    }

    /**
     * 添加request header
     *
     * @param builder HttpRequest.Builder
     */
    private void addHeader(HttpRequest.Builder builder) {
        builder.header(HttpConstants.USER_AGENT, HttpConstants.USER_AGENT_DATA);
    }

    /**
     * GET 请求
     *
     * @param url URL
     * @return 结果
     */
    @Override
    public AdapterHttpResponse get(String url) {
        return this.get(url, null, false);
    }

    /**
     * GET 请求
     *
     * @param url    URL
     * @param params 参数
     * @param encode 是否需要 url encode
     * @return 结果
     */
    @Override
    public AdapterHttpResponse get(String url, Map<String, String> params, boolean encode) {
        return this.get(url, params, null, encode);
    }

    /**
     * GET 请求
     *
     * @param url    URL
     * @param params 参数
     * @param header 请求头
     * @param encode 是否需要 url encode
     * @return 结果
     */
    @Override
    public AdapterHttpResponse get(String url, Map<String, String> params, HttpHeader header, boolean encode) {
        String baseUrl = Strings.CS.appendIfMissing(url, "?", "&");
        String reqUrl = baseUrl + MapUtil.parseMapToString(params, encode);

        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(reqUrl)).GET().timeout(Duration.ofMillis(httpConfig.getTimeout()));

        if (header != null) {
            MapUtil.forEach(header.getHeaders(), builder::header);
        }

        return execute(builder);
    }

    /**
     * POST 请求
     *
     * @param url URL
     * @return 结果
     */
    @Override
    public AdapterHttpResponse post(String url) {
        return this.post(url, null);
    }

    /**
     * POST 请求
     *
     * @param url  URL
     * @param data JSON 参数
     * @return 结果
     */
    @Override
    public AdapterHttpResponse post(String url, String data) {
        return this.post(url, data, null);
    }

    /**
     * POST 请求
     *
     * @param url    URL
     * @param data   JSON 参数
     * @param header 请求头
     * @return 结果
     */
    @Override
    public AdapterHttpResponse post(String url, String data, HttpHeader header) {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofMillis(httpConfig.getTimeout()));

        if (StringUtils.isNotEmpty(data)) {
            builder.POST(HttpRequest.BodyPublishers.ofString(data, HttpConstants.DEFAULT_ENCODING));
            boolean formBody = header != null && header.getHeaders().entrySet().stream()
                    .anyMatch(entry -> HttpConstants.CONTENT_TYPE.equalsIgnoreCase(entry.getKey())
                            && "application/x-www-form-urlencoded".equalsIgnoreCase(entry.getValue()));
            if (!formBody) {
                builder.header(HttpConstants.CONTENT_ENCODING, HttpConstants.DEFAULT_ENCODING.displayName());
            }
            if (header == null || header.getHeaders().keySet().stream()
                    .noneMatch(HttpConstants.CONTENT_TYPE::equalsIgnoreCase)) {
                builder.header(HttpConstants.CONTENT_TYPE, HttpConstants.CONTENT_TYPE_JSON);
            }
        } else {
            builder.POST(HttpRequest.BodyPublishers.noBody());
        }

        if (header != null) {
            MapUtil.forEach(header.getHeaders(), builder::header);
        }

        return this.execute(builder);
    }

    /**
     * POST 请求
     *
     * @param url    URL
     * @param params form 参数
     * @param encode 是否需要 url encode
     * @return 结果
     */
    @Override
    public AdapterHttpResponse post(String url, Map<String, String> params, boolean encode) {
        return this.post(url, params, null, encode);
    }

    /**
     * POST 请求
     *
     * @param url    URL
     * @param params form 参数
     * @param header 请求头
     * @param encode 是否需要 url encode
     * @return 结果
     */
    @Override
    public AdapterHttpResponse post(String url, Map<String, String> params, HttpHeader header, boolean encode) {
        String baseUrl = Strings.CS.appendIfMissing(url, "?", "&");
        String reqUrl = baseUrl + MapUtil.parseMapToString(params, encode);
        return this.post(reqUrl, null, header);
    }

    public class JdkHttpProxySelector extends ProxySelector {
        private HttpConfig httpConfig;

        public JdkHttpProxySelector(HttpConfig httpConfig) {
            this.httpConfig = httpConfig;
        }

        @Override
        public List<Proxy> select(URI uri) {
            return Collections.singletonList(httpConfig.getProxy());
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            throw new AuthHttpException("Proxy connect failed!");
        }
    }

}
