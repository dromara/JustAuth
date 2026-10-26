package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;

/**
 * 钉钉二维码登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthDingTalkRequest extends AbstractAuthDingtalkRequest {

    public AuthDingTalkRequest(AuthConfig config) {
        super(config, AuthDefaultSource.DINGTALK);
    }

    public AuthDingTalkRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.DINGTALK, authStateCache);
    }
}
