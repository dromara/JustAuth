package org.dromara.anduin.http;

import org.dromara.anduin.exception.AuthHttpException;
import org.apache.commons.lang3.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

public class HttpUrlEncoding {

    /**
     * 编码
     *
     * @param value str
     * @return encode str
     */
    public static String encode(String value) {
        if (value == null) {
            return "";
        }
        try {
            String encoded = URLEncoder.encode(value, HttpConstants.DEFAULT_ENCODING.displayName());
            return encoded.replace("+", "%20").replace("*", "%2A").replace("~", "%7E").replace("/", "%2F");
        } catch (UnsupportedEncodingException e) {
            throw new AuthHttpException("Failed To Encode Uri", e);
        }
    }

    /**
     * 解码URL<br>
     * 将%开头的16进制表示的内容解码。
     *
     * @param url URL
     * @return 解码后的URL
     * @throws UtilException UnsupportedEncodingException
     */
    public static String decode(String url) throws AuthHttpException {
        if (StringUtils.isEmpty(url)) {
            return url;
        }
        try {
            return URLDecoder.decode(url, HttpConstants.DEFAULT_ENCODING.displayName());
        } catch (UnsupportedEncodingException e) {
            throw new AuthHttpException("Unsupported encoding", e);
        }
    }
}
