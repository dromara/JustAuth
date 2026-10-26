package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.utils.GlobalAuthUtils;

/**
 * 微软登录
 * update 2021-08-24  mroldx (xzfqq5201314@gmail.com)
 *
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.5.0
 */
public class AuthMicrosoftRequest extends AbstractAuthMicrosoftRequest {

    public AuthMicrosoftRequest(AuthConfig config) {
        super(config, AuthDefaultSource.MICROSOFT);
    }

    public AuthMicrosoftRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.MICROSOFT, authStateCache);
    }

    @Override
    protected void checkConfig(AuthConfig config) {
        super.checkConfig(config);
        // 微软的回调地址必须为https的链接或者localhost,不允许使用http
        if (AuthDefaultSource.MICROSOFT == source && !GlobalAuthUtils.isHttpsProtocolOrLocalHost(config.getRedirectUri())) {
            // Microsoft's redirect uri must use the HTTPS or localhost
            throw new AuthException(AuthResponseStatus.ILLEGAL_REDIRECT_URI, source);
        }
    }

}
