package me.zhyd.oauth.http;

import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdapterHttpResponse {
	boolean success;
	int code;
	Map<String, List<String>> headers;
	String body;
	String error;
}
