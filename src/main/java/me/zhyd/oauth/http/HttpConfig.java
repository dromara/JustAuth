package me.zhyd.oauth.http;

import java.net.Proxy;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class HttpConfig {
	/**
	 * 超时时长，单位毫秒
	 */
	int timeout = HttpConstants.DEFAULT_TIMEOUT;
	
	/**
	 * 代理配置
	 */
	private Proxy proxy;
}
