package me.zhyd.oauth.request;

import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.utils.AuthStateUtils;
import org.junit.jupiter.api.Test;

public class AuthWeChatEnterpriseWebRequestTest {

    @Test
    public void authorize() {
        AuthRequest request = new AuthWeChatEnterpriseWebRequest(AuthConfig.builder()
                .clientId("a")
                .clientSecret("a")
                .redirectUri("https://www.justauth.cn")
                .build());
        System.out.println(request.authorize(AuthStateUtils.createState()));
    }
}
