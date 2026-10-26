package org.dromara.anduin.cache;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

public class AuthStateCacheTest {

    @Test
    public void cache1() throws InterruptedException {
        AuthDefaultStateCache.INSTANCE.cache("key", "value");
        Assertions.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));

        TimeUnit.MILLISECONDS.sleep(4);
        Assertions.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));
    }

    @Test
    public void cache2() throws InterruptedException {
        AuthDefaultStateCache.INSTANCE.cache("key", "value");
        Assertions.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));

        // 没过期
        Assertions.assertEquals("value", AuthDefaultStateCache.INSTANCE.get("key"));

        AuthDefaultStateCache.INSTANCE.expire("key");
        // 过期
        Assertions.assertNull(AuthDefaultStateCache.INSTANCE.get("key"));
    }
}
