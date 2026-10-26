package org.dromara.anduin.request;

import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.utils.GlobalAuthUtils;

import org.apache.commons.lang3.StringUtils;

/**
 * <p>
 * 新版企业微信 Web 登录，参考 <a href="https://developer.work.weixin.qq.com/document/path/98152">https://developer.work.weixin.qq.com/document/path/98152</a>
 * </p>
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.7
 */
public class AuthWeChatEnterpriseQrcodeV2Request extends AbstractAuthWeChatEnterpriseRequest {
    public AuthWeChatEnterpriseQrcodeV2Request(AuthConfig config) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_V2);
    }

    public AuthWeChatEnterpriseQrcodeV2Request(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_V2, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam("login_type", config.getLoginType())
                // 登录类型为企业自建应用/服务商代开发应用时填企业 CorpID，第三方登录时填登录授权 SuiteID
                .queryParam(Keys.OAUTH2.APPID, config.getClientId())
                // 企业自建应用/服务商代开发应用 AgentID，当login_type=CorpApp时填写
                .queryParam("agentid", config.getAgentId())
                .queryParam(Keys.OAUTH2.REDIRECT_URI, GlobalAuthUtils.urlEncode(config.getRedirectUri()))
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .queryParam(Keys.USERINFO.LANG, config.getLang())
                .build()
                .concat("#wechat_redirect");
    }

    @Override
    protected void checkConfig(AuthConfig config) {
        super.checkConfig(config);
        if ("CorpApp".equals(config.getLoginType()) && StringUtils.isEmpty(config.getAgentId())) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_WECHAT_AGENT_ID, source);
        }
    }
}
