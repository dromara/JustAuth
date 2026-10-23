package me.zhyd.oauth.model;

import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.config.AuthExtendSource;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.utils.JsonUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AuthUserTest {

    @Test
    public void serialize() {

        AuthUser user = AuthUser.builder()
                .nickname("test")
                .build();
        String json = JsonUtils.toJson(user);
        Assertions.assertEquals("{\"avatar\":null,\"blog\":null,\"company\":null,\"email\":null,\"gender\":null,\"location\":null,\"nickname\":\"test\",\"rawUserInfo\":null,\"remark\":null,\"snapshotUser\":false,\"source\":null,\"token\":null,\"username\":null,\"uuid\":null}", json);

    }

    @Test
    public void deserialize() {
        AuthUser user = AuthUser.builder()
                .nickname("test")
                .build();
        String json = JsonUtils.toJson(user);

        AuthUser deserializeUser = JsonUtils.toObject(json, AuthUser.class);
        Assertions.assertEquals("test", deserializeUser.getNickname());
    }

    @Test
    public void source() {
        AuthSource source = AuthDefaultSource.HUAWEI;
        AuthUser user = AuthUser.builder()
                .source(source.toString())
                .build();
        Assertions.assertEquals("HUAWEI", user.getSource());

        source = AuthExtendSource.OTHER;
        user = AuthUser.builder()
                .source(source.toString())
                .build();
        Assertions.assertEquals("OTHER", user.getSource());

        source = AuthDefaultSource.HUAWEI;
        Assertions.assertEquals(source, AuthDefaultSource.HUAWEI);

        source = AuthExtendSource.OTHER;
        Assertions.assertEquals(source, AuthExtendSource.OTHER);
    }

}
