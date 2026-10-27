package org.dromara.anduin.http;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.net.Proxy;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class HttpConfig {
    /**
     * 超时时长，单位毫秒
     */
    int timeout = 3000;

    /**
     * 代理配置
     */
    private Proxy proxy;
}
