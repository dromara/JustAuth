package org.dromara.anduin.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JsonPath用法测试
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 */
public class JsonPathTest {

    @Test
    public void jsonPath() {
        List<Map<String, Map<String, Object>>> list = new ArrayList<>();

        Map<String, Map<String, Object>> map = new HashMap<>();
        Map<String, Object> node = new HashMap<>();
        node.put("emailAddress", "xxxx");
        map.put("handle~", node);
        list.add(map);


        Map<String, Object> master = new HashMap<>();
        master.put("elements", list);

        JsonNode emailObj = JsonUtils.toNode(JsonUtils.toJson(master));

        JsonNode elements = JsonNodeUtils.findArrayNode(emailObj, "elements");

        Assertions.assertFalse(elements == null || elements.isEmpty(), "elements is null");

        JsonNode element = elements.get(0);
        Assertions.assertNotNull(element, "element is null");

        JsonNode handle = JsonNodeUtils.findObjectNode(element, "handle~");
        Assertions.assertNotNull(handle, "handle is null");
        String address = JsonNodeUtils.findStringValue(handle, "emailAddress");
        Assertions.assertEquals("xxxx", address);
    }
}
