package org.dromara.anduin.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Ticker;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class AuthDefaultCacheIsolationTest {
    @Test
    void constructingCacheDoesNotResetEarlierCache() {
        AuthDefaultCache first = new AuthDefaultCache();
        first.set("state", "first");
        AuthDefaultCache second = new AuthDefaultCache();
        assertEquals("first", first.get("state"));
        assertNull(second.get("state"));
        second.set("state", "second");
        assertEquals("first", first.get("state"));
        second.expire("state");
        assertNull(second.get("state"));
        assertEquals("first", first.get("state"));
    }

    @Test
    void constructingCacheDoesNotResetDefaultSingleton() {
        String key = "cache-isolation-" + java.util.UUID.randomUUID();
        AuthDefaultStateCache.INSTANCE.cache(key, "singleton");
        try {
            new AuthDefaultCache();
            assertEquals("singleton", AuthDefaultStateCache.INSTANCE.get(key));
        } finally {
            AuthDefaultStateCache.INSTANCE.expire(key);
        }
    }

    @Test
    void expiresAtConfiguredBoundaryWithoutSleeping() throws Exception {
        AuthDefaultCache cache = new AuthDefaultCache();
        AtomicLong now = new AtomicLong();
        Cache<?, ?> caffeine = (Cache<?, ?>) field(cache, "stateCache").get(cache);
        Object local = field(caffeine, "cache").get(caffeine);
        field(local, "ticker").set(local, (Ticker) now::get);
        cache.set("state", "value");
        now.set(TimeUnit.MINUTES.toNanos(5) - 1);
        assertEquals("value", cache.get("state"));
        assertTrue(cache.containsKey("state"));
        now.incrementAndGet();
        assertNull(cache.get("state"));
        assertFalse(cache.containsKey("state"));
    }

    @Test
    void blankValuesAreNotPresentAndInvalidationRemovesValue() {
        AuthDefaultCache cache = new AuthDefaultCache();
        cache.set("blank", " ");
        assertFalse(cache.containsKey("blank"));
        assertEquals(" ", cache.get("blank"));
        cache.set("state", "value");
        assertTrue(cache.containsKey("state"));
        cache.expire("state");
        assertNull(cache.get("state"));
        assertFalse(cache.containsKey("state"));
    }

    private static Field field(Object instance, String name) throws NoSuchFieldException {
        for (Class<?> type = instance.getClass(); type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
                // Caffeine stores its clock in a generated superclass.
            }
        }
        throw new NoSuchFieldException(name);
    }
}
