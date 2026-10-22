package me.zhyd.oauth.http;

import me.zhyd.oauth.exception.AuthHttpException;
import me.zhyd.oauth.http.adapter.JdkHttpAdapter;

public class UnifiedHttpClient {
	
	static HttpClientAdapter httpClientAdapter;
	
	private UnifiedHttpClient() {
	}
	
	public static HttpClientAdapter getAdapter() {
		if(httpClientAdapter != null) {
			return httpClientAdapter;
		}
		
		ClassLoader classLoader = UnifiedHttpClient.class.getClassLoader();

		// 基于 java 17
		if (isPresent("java.net.http.HttpClient", classLoader)) {
			httpClientAdapter = new JdkHttpAdapter();
		}
				
		if (httpClientAdapter == null) {
			throw new AuthHttpException("Environment not have HttpClient implement !");
		}

		return httpClientAdapter;
	}
	
	/**
	 * 判断来是否加载
	 * @param className
	 * @param classLoader
	 * @return boolean
	 */
	public static boolean isPresent(String className, ClassLoader classLoader) {
		try {
			Class.forName(className, true, classLoader);
			return true;
		} catch (Throwable ex) {
			return false;
		}
	}
}
