package me.zhyd.oauth.http;

import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.request.AuthWeChatOpenRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * <p>
 * UrlBuilder测试类
 * </p>
 *
 * @author yangkai.shen (https://xkcoding.com)
 * @date Created in 2019-07-18 16:36
 */
public class UrlBuilderTest {
    @Test
    public void testUrlBuilder() {
        AuthConfig config = AuthConfig.builder()
                .clientId("appid-110110110")
                .clientSecret("secret-110110110")
                .redirectUri("https://xkcoding.com")
                .build();
        String build = UrlBuilder.fromBaseUrl(AuthDefaultSource.WECHAT_OPEN.authorize())
                .queryParam(Keys.APPID, config.getClientId())
                .queryParam(Keys.OAUTH2__REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2__RESPONSE_TYPE, Keys.OAUTH2__CODE)
                .queryParam(Keys.OAUTH2__SCOPE, "snsapi_login")
                .queryParam(Keys.OAUTH2__STATE, "")
                .build(false);
        System.out.println(build);
        AuthWeChatOpenRequest request = new AuthWeChatOpenRequest(config);
        String authorize = request.authorize(Keys.OAUTH2__STATE);
        System.out.println(authorize);
    }

    @Test
    public void build() {
        String url = UrlBuilder.fromBaseUrl("https://www.zhyd.me")
                .queryParam(Keys.NAME, "yadong.zhang")
                .build();
        Assertions.assertEquals("https://www.zhyd.me?name=yadong.zhang", url);

        url = UrlBuilder.fromBaseUrl("https://www.zhyd.me")
                .queryParam(Keys.NAME, "yadong.zhang")
                .queryParam("github", "https://github.com/zhangyd-c")
                .build();
        Assertions.assertEquals("https://www.zhyd.me?name=yadong.zhang&github=https://github.com/zhangyd-c", url);
    }

    @Test
    public void build1() {
        String url = UrlBuilder.fromBaseUrl("https://www.zhyd.me")
                .queryParam(Keys.NAME, "yadong.zhang")
                .build(true);
        Assertions.assertEquals("https://www.zhyd.me?name=yadong.zhang", url);

        url = UrlBuilder.fromBaseUrl("https://www.zhyd.me")
                .queryParam(Keys.NAME, "yadong.zhang")
                .queryParam("github", "https://github.com/zhangyd-c")
                .build(true);
        Assertions.assertEquals("https://www.zhyd.me?name=yadong.zhang&github=https%3A%2F%2Fgithub.com%2Fzhangyd-c", url);
    }
}
