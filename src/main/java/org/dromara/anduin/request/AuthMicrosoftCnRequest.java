package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.utils.GlobalAuthUtils;

/**
 * 微软中国登录(世纪华联)
 *
 * @author mroldx (xzfqq5201314@gmail.com)
 * @since 1.16.4
 */
public class AuthMicrosoftCnRequest extends AbstractAuthMicrosoftRequest {

    public AuthMicrosoftCnRequest(AuthConfig config) {
        super(config, AuthDefaultSource.MICROSOFT_CN);
    }

    public AuthMicrosoftCnRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.MICROSOFT_CN, authStateCache);
    }

    @Override
    protected void checkConfig(AuthConfig config) {
        super.checkConfig(config);
        // 微软中国的回调地址必须为https的链接或者localhost,不允许使用http
        if (AuthDefaultSource.MICROSOFT_CN == source && !GlobalAuthUtils.isHttpsProtocolOrLocalHost(config.getRedirectUri())) {
            // Microsoft's redirect uri must use the HTTPS or localhost
            throw new AuthException(AuthResponseStatus.ILLEGAL_REDIRECT_URI, source);
        }
    }

}
