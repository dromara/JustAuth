package me.zhyd.oauth.request;

import com.alipay.api.response.AlipaySystemOauthTokenResponse;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.model.AuthToken;

/**
 * <p>Description: Alipay Request 抽象定义 </p>
 *
 * @author : gengwei_zheng
 * @date : 2026/10/22 17:27
 */
public abstract class AbstractAuthAlipayRequest extends AuthDefaultRequest {

    protected AbstractAuthAlipayRequest(AuthConfig config, AuthSource source) {
        super(config, source);
    }

    protected AbstractAuthAlipayRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        super(config, source, authStateCache);
    }

    protected AuthToken getAccessToken(AlipaySystemOauthTokenResponse response) {
        return AuthToken.builder()
                .accessToken(response.getAccessToken())
                .expireIn(Integer.parseInt(response.getExpiresIn()))
                .refreshToken(response.getRefreshToken())
                .uid(response.getUserId())
                .build();
    }
}
