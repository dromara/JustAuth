package me.zhyd.oauth.model;

import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.config.AuthExtendSource;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.utils.JsonUtils;
import org.junit.Assert;
import org.junit.Test;

public class AuthUserTest {

    @Test
    public void serialize() {

        AuthUser user = AuthUser.builder()
                .nickname("test")
                .build();
        String json = JsonUtils.toJson(user);
        Assert.assertEquals("{\"nickname\":\"test\",\"snapshotUser\":false}", json);

    }

    @Test
    public void deserialize() {
        AuthUser user = AuthUser.builder()
                .nickname("test")
                .build();
        String json = JsonUtils.toJson(user);

        AuthUser deserializeUser = JsonUtils.toObject(json, AuthUser.class);
        Assert.assertEquals("test", deserializeUser.getNickname());
    }

    @Test
    public void source() {
        AuthSource source = AuthDefaultSource.HUAWEI;
        AuthUser user = AuthUser.builder()
                .source(source.toString())
                .build();
        Assert.assertEquals("HUAWEI", user.getSource());

        source = AuthExtendSource.OTHER;
        user = AuthUser.builder()
                .source(source.toString())
                .build();
        Assert.assertEquals("OTHER", user.getSource());

        source = AuthDefaultSource.HUAWEI;
        Assert.assertEquals(source, AuthDefaultSource.HUAWEI);

        source = AuthExtendSource.OTHER;
        Assert.assertEquals(source, AuthExtendSource.OTHER);
    }

}
