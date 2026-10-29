package org.dromara.anduin.utils;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import static org.junit.jupiter.api.Assertions.*;

class JsonNodeScalarRegressionTest {
    @Test void stringLookupPreservesNumericAndBooleanScalarValues() {
        JsonNode node = JsonUtils.getObjectMapper().readTree("{\"id\":4294967296,\"sex\":2,\"enabled\":true,"
                + "\"disabled\":false,\"name\":\"Ada\",\"decimal\":1.25}");
        assertEquals("4294967296", JsonNodeUtils.findStringValue(node, "id"));
        assertEquals("2", JsonNodeUtils.findStringValue(node, "sex"));
        assertEquals("true", JsonNodeUtils.findStringValue(node, "enabled"));
        assertEquals("false", JsonNodeUtils.findStringValue(node, "disabled"));
        assertEquals("1.25", JsonNodeUtils.findStringValue(node, "decimal"));
        assertEquals("Ada", JsonNodeUtils.findStringValue(node, "name"));
    }

    @Test void stringLookupDoesNotConvertNullOrContainers() {
        JsonNode node = JsonUtils.getObjectMapper().readTree("{\"empty\":null,\"object\":{},\"array\":[]}");
        assertNull(JsonNodeUtils.findStringValue(node, "empty"));
        assertNull(JsonNodeUtils.findStringValue(node, "object"));
        assertNull(JsonNodeUtils.findStringValue(node, "array"));
        assertNull(JsonNodeUtils.findStringValue(node, "missing"));
        assertNull(JsonNodeUtils.findStringValue(null, "id"));
    }
}
