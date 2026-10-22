package me.zhyd.oauth.utils;

import org.junit.Assert;
import org.junit.Test;
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

        Assert.assertFalse("elements is null", elements == null || elements.isEmpty());

        JsonNode element = elements.get(0);
        Assert.assertNotNull("element is null", element);

        JsonNode handle = JsonNodeUtils.findObjectNode(element, "handle~");
        Assert.assertNotNull("handle is null", handle);
        String address =  JsonNodeUtils.findStringValue(handle, "emailAddress");
        Assert.assertEquals("xxxx", address);
    }
}
