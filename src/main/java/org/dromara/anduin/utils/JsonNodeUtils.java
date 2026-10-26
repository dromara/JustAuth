/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2020-2030 郑庚伟 ZHENGGENGWEI (码匠君), <herodotus@aliyun.com> Licensed under the AGPL License
 *
 * This file is part of Herodotus Stirrup.
 *
 * Herodotus Stirrup is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Herodotus Stirrup is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.herodotus.cn>.
 */

package org.dromara.anduin.utils;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.MissingNode;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * <p>Description: This class is a straight copy from Spring Authorization Server.</p>
 *
 * @author : gengwei.zheng
 * @date : 2022/10/24 15:31
 */
public class JsonNodeUtils {

    public static final TypeReference<Instant> INSTANT = new TypeReference<>() {
    };

    public static final TypeReference<Set<String>> STRING_SET = new TypeReference<>() {
    };

    public static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP = new TypeReference<>() {
    };

    public static boolean containsKey(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return false;
        }

        return jsonNode.hasNonNull(fieldName);
    }

    public static String findStringValue(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return null;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return (value != null && !value.isNull() && value.isString()) ? value.asString() : null;
    }

    public static boolean findBooleanValue(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return false;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return value != null && !value.isNull() && value.isBoolean() && value.asBoolean();
    }

    public static int findIntValue(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return 0;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return (value != null && !value.isNull() && value.isInt()) ? value.asInt() : 0;
    }

    public static long findLongValue(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return 0L;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return (value != null && !value.isNull() && value.isLong()) ? value.asLong() : 0L;
    }


    public static <T> T findValue(JsonNode jsonNode, String fieldName, TypeReference<T> valueTypeReference, DeserializationContext context) {
        if (jsonNode == null) {
            return null;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return value != null && value.isContainer() ? context.readTreeAsValue(value, context.getTypeFactory().constructType(valueTypeReference)) : null;
    }

    public static JsonNode findObjectNode(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return null;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return (value != null && value.isObject()) ? value : null;
    }

    public static JsonNode findArrayNode(JsonNode jsonNode, String fieldName) {
        if (jsonNode == null) {
            return null;
        }
        JsonNode value = jsonNode.findValue(fieldName);
        return (value != null && value.isArray()) ? value : null;
    }

    public static JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
