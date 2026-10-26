package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.scope.AuthWeChatEnterpriseWebScope;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.GlobalAuthUtils;

/**
 * <p>
 * 企业微信网页登录
 * </p>
 *
 * @author liguanhua (347826496(a)qq.com)
 * @since 1.15.9
 */
public class AuthWeChatEnterpriseWebRequest extends AbstractAuthWeChatEnterpriseRequest {
    public AuthWeChatEnterpriseWebRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_WEB);
    }

    public AuthWeChatEnterpriseWebRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_WEB, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                .queryParam("agentid", config.getAgentId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, GlobalAuthUtils.urlEncode(config.getRedirectUri()))
                .queryParam(Keys.OAUTH2.RESPONSE_TYPE, Keys.OAUTH2.CODE)
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthWeChatEnterpriseWebScope.values())))
                .queryParam(Keys.OAUTH2.STATE, getRealState(state).concat("#wechat_redirect"))
                .build();
    }
}
