package org.dromara.anduin.request;

import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthStateUtils;
import org.dromara.anduin.utils.JsonUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * 自定义扩展的第三方request的测试类，用于演示具体的用法
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @version 1.0
 * @since 1.12.0
 */
public class AuthExtendRequestTest {

    @Test
    public void authorize() {
        AuthRequest request = new AuthExtendRequest(AuthConfig.builder()
                .clientId(Keys.PARAM.CLIENT_ID)
                .clientSecret(Keys.PARAM.CLIENT_SECRET)
                .redirectUri("http://redirectUri")
                .build());
        String authorize = request.authorize(AuthStateUtils.createState());
        System.out.println(authorize);
        Assertions.assertNotNull(authorize);
    }

    @Test
    public void login() {
        AuthRequest request = new AuthExtendRequest(AuthConfig.builder()
                .clientId(Keys.PARAM.CLIENT_ID)
                .clientSecret(Keys.PARAM.CLIENT_SECRET)
                .redirectUri("http://redirectUri")
                .build());

        String state = AuthStateUtils.createState();
        request.authorize(state);
        AuthCallback callback = AuthCallback.builder()
                .code(Keys.OAUTH2.CODE)
                .state(state)
                .build();
        AuthResponse<AuthUser> response = request.login(callback);
        Assertions.assertNotNull(response);

        AuthUser user = response.getData();
        Assertions.assertNotNull(user);
        System.out.println(JsonUtils.toJson(user));
    }

    @Test
    public void revoke() {
        AuthRequest request = new AuthExtendRequest(AuthConfig.builder()
                .clientId(Keys.PARAM.CLIENT_ID)
                .clientSecret(Keys.PARAM.CLIENT_SECRET)
                .redirectUri("http://redirectUri")
                .build());

        AuthResponse<?> response = request.revoke(AuthToken.builder().build());
        Assertions.assertNotNull(response);
        System.out.println(JsonUtils.toJson(response));
    }

    @Test
    public void refresh() {
        AuthRequest request = new AuthExtendRequest(AuthConfig.builder()
                .clientId(Keys.PARAM.CLIENT_ID)
                .clientSecret(Keys.PARAM.CLIENT_SECRET)
                .redirectUri("http://redirectUri")
                .build());

        AuthResponse<AuthToken> response = request.refresh(AuthToken.builder().build());
        Assertions.assertNotNull(response);
        System.out.println(JsonUtils.toJson(response.getData()));

    }
}
