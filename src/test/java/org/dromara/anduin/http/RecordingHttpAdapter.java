package org.dromara.anduin.http;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;

/** Records the protocol boundary while keeping provider parsing and mapping real. */
public final class RecordingHttpAdapter implements HttpClientAdapter, AutoCloseable {
    public static final String RESOURCE = "UnifiedHttpClient.httpClientAdapter";
    private final HttpClientAdapter previous;
    private final Deque<String> responses = new ArrayDeque<>();
    private final List<Request> requests = new ArrayList<>();

    public RecordingHttpAdapter() {
        previous = UnifiedHttpClient.httpClientAdapter;
        UnifiedHttpClient.httpClientAdapter = this;
    }

    public void respond(String body) {
        responses.addLast(body);
    }

    public List<Request> requests() {
        return List.copyOf(requests);
    }

    private AdapterHttpResponse record(String method, String url, String body, Map<String, String> params,
                                       HttpHeader header, boolean encode) {
        requests.add(new Request(method, url, body, params == null ? Map.of() : Map.copyOf(params),
                header == null ? Map.of() : Map.copyOf(header.getHeaders()), encode));
        if (responses.isEmpty()) {
            throw new AssertionError("Unexpected HTTP request: " + method + " " + url);
        }
        return new AdapterHttpResponse(true, 200, Map.of(), responses.removeFirst(), null);
    }

    @Override public AdapterHttpResponse get(String url) { return record("GET", url, null, null, null, false); }
    @Override public AdapterHttpResponse get(String url, Map<String, String> params, boolean encode) {
        return record("GET", url, null, params, null, encode);
    }
    @Override public AdapterHttpResponse get(String url, Map<String, String> params, HttpHeader header, boolean encode) {
        return record("GET", url, null, params, header, encode);
    }
    @Override public AdapterHttpResponse post(String url) { return record("POST", url, null, null, null, false); }
    @Override public AdapterHttpResponse post(String url, String data) { return record("POST", url, data, null, null, false); }
    @Override public AdapterHttpResponse post(String url, String data, HttpHeader header) {
        return record("POST", url, data, null, header, false);
    }
    @Override public AdapterHttpResponse post(String url, Map<String, String> params, boolean encode) {
        return record("POST", url, null, params, null, encode);
    }
    @Override public AdapterHttpResponse post(String url, Map<String, String> params, HttpHeader header, boolean encode) {
        return record("POST", url, null, params, header, encode);
    }

    @Override public void close() {
        UnifiedHttpClient.httpClientAdapter = previous;
    }

    public record Request(String method, String url, String body, Map<String, String> params,
                          Map<String, String> headers, boolean encode) { }
}
