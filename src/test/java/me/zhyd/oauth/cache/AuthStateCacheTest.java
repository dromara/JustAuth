package me.zhyd.oauth.cache;

import org.junit.Assert;
import org.junit.Test;

import java.util.concurrent.TimeUnit;

public class AuthStateCacheTest {

    @Test
    public void cache1() throws InterruptedException {
        AuthDefaultStateCache.INSTANCE.cache("key", "value");
        Assert.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));

        TimeUnit.MILLISECONDS.sleep(4);
        Assert.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));
    }

    @Test
    public void cache2() throws InterruptedException {
        AuthDefaultStateCache.INSTANCE.cache("key", "value", 10);
        Assert.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));

        // 没过期
        TimeUnit.MILLISECONDS.sleep(5);
        Assert.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));

        // 过期
        TimeUnit.MILLISECONDS.sleep(6);
        Assert.assertNull(AuthDefaultStateCache.INSTANCE.get("key"));
    }
}
