package org.dromara.anduin.request;

import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.utils.AuthStateUtils;
import org.junit.jupiter.api.Test;

public class AuthWeChatMpRequestTest {

    @Test
    public void authorize() {

        AuthRequest request = new AuthWeChatMpRequest(AuthConfig.builder()
                .clientId("a")
                .clientSecret("a")
                .redirectUri("https://www.justauth.cn")
                .build());
        System.out.println(request.authorize(AuthStateUtils.createState()));
    }
}
