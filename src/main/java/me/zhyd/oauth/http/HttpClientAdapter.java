package me.zhyd.oauth.http;

import java.util.Map;

public interface  HttpClientAdapter {
	/**
	 * GET 请求
	 *
	 * @param url URL
	 * @return 结果
	 */
	public AdapterHttpResponse get(String url) ;

	/**
	 * GET 请求
	 *
	 * @param url    URL
	 * @param params 参数
	 * @param encode 是否需要 url encode
	 * @return 结果
	 */
	public AdapterHttpResponse get(String url, Map<String, String> params, boolean encode) ;

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
	public AdapterHttpResponse post(String url) ;

	/**
	 * POST 请求
	 *
	 * @param url  URL
	 * @param data JSON 参数
	 * @return 结果
	 */
	public AdapterHttpResponse post(String url, String data) ;

	/**
	 * POST 请求
	 *
	 * @param url    URL
	 * @param data   JSON 参数
	 * @param header 请求头
	 * @return 结果
	 */
	public AdapterHttpResponse post(String url, String data, HttpHeader header) ;

	/**
	 * POST 请求
	 *
	 * @param url    URL
	 * @param params form 参数
	 * @param encode 是否需要 url encode
	 * @return 结果
	 */
	public AdapterHttpResponse post(String url, Map<String, String> params, boolean encode) ;

	/**
	 * POST 请求
	 *
	 * @param url    URL
	 * @param params form 参数
	 * @param header 请求头
	 * @param encode 是否需要 url encode
	 * @return 结果
	 */
	public AdapterHttpResponse post(String url, Map<String, String> params, HttpHeader header, boolean encode) ;
}
