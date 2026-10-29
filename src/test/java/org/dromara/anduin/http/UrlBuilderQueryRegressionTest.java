package org.dromara.anduin.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UrlBuilderQueryRegressionTest {
    @Test void appendsToExistingQueryWithoutChangingState() {
        assertEquals("https://example.com/authorize?state=csrf&scope=profile",
                UrlBuilder.fromBaseUrl("https://example.com/authorize?state=csrf")
                        .queryParam("scope", "profile").build());
    }

    @Test void doesNotDuplicateTrailingQueryDelimiter() {
        for (String url : new String[]{"https://example.com/authorize?", "https://example.com/authorize?state=csrf&"}) {
            assertEquals(url + "scope=profile", UrlBuilder.fromBaseUrl(url).queryParam("scope", "profile").build());
        }
    }
}
