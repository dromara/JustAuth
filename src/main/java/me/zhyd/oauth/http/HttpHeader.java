package me.zhyd.oauth.http;

import java.util.HashMap;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class HttpHeader {
	Map<String, String> headers;

	public HttpHeader() {
		this.headers = new HashMap<>(10);
	}

	public HttpHeader(Map<String, String> headers) {
		this.headers = headers;
	}

	public HttpHeader add(String key, String value) {
		this.headers.put(key, value);
		return this;
	}

	public HttpHeader addAll(Map<String, String> headers) {
		this.headers.putAll(headers);
		return this;
	}
}
