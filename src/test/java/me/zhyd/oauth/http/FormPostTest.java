package me.zhyd.oauth.http;

import com.sun.net.httpserver.HttpServer;
import me.zhyd.oauth.http.adapter.JdkHttpAdapter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 表单请求与现有 JSON POST 的协议回归测试。
 *
 * @author AprilWind
 */
public class FormPostTest {

    @Test
    public void shouldSendFormBodyWithOneContentTypeAndPreserveJsonPost() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String result = exchange.getRequestURI().getRawQuery() + "|" + body + "|"
                    + exchange.getRequestHeaders().get("Content-Type") + "|"
                    + exchange.getRequestHeaders().getFirst("Authorization") + "|"
                    + exchange.getRequestHeaders().getFirst("Content-Encoding");
            byte[] bytes = result.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var output = exchange.getResponseBody()) {
                output.write(bytes);
            }
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/token";
            JdkHttpAdapter adapter = new JdkHttpAdapter();
            AdapterHttpResponse form = adapter.postForm(url, Map.of("secret", "a +&=中文"),
                    new HttpHeader().add("Authorization", "Basic abc"));
            Assertions.assertTrue(form.isSuccess());
            Assertions.assertEquals("null|secret=a+%2B%26%3D%E4%B8%AD%E6%96%87|"
                    + "[application/x-www-form-urlencoded]|Basic abc|null", form.getBody());
            AdapterHttpResponse json = adapter.post(url, "{\"name\":\"test\"}");
            Assertions.assertEquals("null|{\"name\":\"test\"}|[application/json; charset=utf-8]|null|UTF-8", json.getBody());
        } finally {
            server.stop(0);
        }
    }
}
