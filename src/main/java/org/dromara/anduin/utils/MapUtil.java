package org.dromara.anduin.utils;

import org.dromara.anduin.http.HttpConstants;
import org.dromara.anduin.http.HttpUrlEncoding;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.function.BiConsumer;

public class MapUtil {
    /**
     * 遍历
     *
     * @param map    待遍历的 map
     * @param action 操作
     * @param <K>    map键泛型
     * @param <V>    map值泛型
     */
    public static <K, V> void forEach(Map<K, V> map, BiConsumer<? super K, ? super V> action) {
        if (ObjectUtils.isEmpty(map) || action == null) {
            return;
        }
        for (Map.Entry<K, V> entry : map.entrySet()) {
            K k;
            V v;
            try {
                k = entry.getKey();
                v = entry.getValue();
            } catch (IllegalStateException ise) {
                // this usually means the entry is no longer in the map.
                throw new ConcurrentModificationException(ise);
            }
            action.accept(k, v);
        }
    }

    /**
     * map转字符串，转换后的字符串格式为 {@code xxx=xxx&xxx=xxx}
     *
     * @param params 待转换的map
     * @param encode 是否转码
     * @return str
     */
    public static String parseMapToString(Map<String, String> params, boolean encode) {
        List<String> paramList = new ArrayList<>();
        forEach(params, (k, v) -> {
            if (v == null) {
                paramList.add(k + "=");
            } else {
                paramList.add(k + "=" + (encode ? HttpUrlEncoding.encode(v) : v));
            }
        });
        return String.join("&", paramList);
    }

    /**
     * 字符串转map，字符串格式为 {@code xxx=xxx&xxx=xxx}
     *
     * @param str    待转换的字符串
     * @param decode 是否解码
     * @return map
     */
    public static Map<String, String> parseStringToMap(String str, boolean decode) {
        str = preProcess(str);

        Map<String, String> params = new HashMap<>(16);
        if (StringUtils.isEmpty(str)) {
            return params;
        }

        if (!str.contains("&")) {
            params.put(decode(str, decode), HttpConstants.EMPTY);
            return params;
        }

        final int len = str.length();
        String name = null;
        // 未处理字符开始位置
        int pos = 0;
        // 未处理字符结束位置
        int i;
        // 当前字符
        char c;
        for (i = 0; i < len; i++) {
            c = str.charAt(i);
            // 键值对的分界点
            if (c == '=') {
                if (null == name) {
                    // name可以是""
                    name = str.substring(pos, i);
                }
                pos = i + 1;
            }
            // 参数对的分界点
            else if (c == '&') {
                if (null == name && pos != i) {
                    // 对于像&a&这类无参数值的字符串，我们将name为a的值设为""
                    addParam(params, str.substring(pos, i), HttpConstants.EMPTY, decode);
                } else if (name != null) {
                    addParam(params, name, str.substring(pos, i), decode);
                    name = null;
                }
                pos = i + 1;
            }
        }

        // 处理结尾
        if (pos != i) {
            if (name == null) {
                addParam(params, str.substring(pos, i), HttpConstants.EMPTY, decode);
            } else {
                addParam(params, name, str.substring(pos, i), decode);
            }
        } else if (name != null) {
            addParam(params, name, HttpConstants.EMPTY, decode);
        }

        return params;
    }

    private static void addParam(Map<String, String> params, String key, String value, boolean decode) {
        key = decode(key, decode);
        value = decode(value, decode);
        if (params.containsKey(key)) {
            params.put(key, params.get(key) + "," + value);
        } else {
            params.put(key, value);
        }
    }

    private static String decode(String str, boolean decode) {
        return decode ? HttpUrlEncoding.decode(str) : str;
    }


    private static String preProcess(String str) {
        if (StringUtils.isEmpty(str)) {
            return str;
        }
        // 去除 URL 路径信息
        int beginPos = str.indexOf("?");
        if (beginPos > -1) {
            str = str.substring(beginPos + 1);
        }

        // 去除 # 后面的内容
        int endPos = str.indexOf("#");
        if (endPos > -1) {
            str = str.substring(0, endPos);
        }

        return str;
    }
}
