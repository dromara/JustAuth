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

import org.apache.commons.lang3.ObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.json.JsonReadFeature;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.type.TypeFactory;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * @author gengwei.zheng
 */
public class JsonUtils {

    private static final Logger log = LoggerFactory.getLogger(JsonUtils.class);

    private static volatile JsonUtils instance;

    private ObjectMapper objectMapper;

    private JsonUtils() {
        this.objectMapper = JsonMapper.builder()
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .enable(JsonReadFeature.ALLOW_SINGLE_QUOTES)
                .enable(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS)
                .build();
    }

    public static JsonUtils getInstance() {
        if (ObjectUtils.isEmpty(instance)) {
            synchronized (JsonUtils.class) {
                if (ObjectUtils.isEmpty(instance)) {
                    instance = new JsonUtils();
                }
            }
        }

        return instance;
    }

    private ObjectMapper objectMapper() {
        return objectMapper;
    }

    private void objectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public static ObjectMapper getObjectMapper() {
        return getInstance().objectMapper();
    }

    public static void setObjectMapper(ObjectMapper objectMapper) {
        getInstance().objectMapper(objectMapper);
    }

    public static <T> String toJson(T domain) {
        try {
            return getObjectMapper().writeValueAsString(domain);
        } catch (JacksonException e) {
            log.error("Jackson json processing error, when to json! {}", e.getMessage());
            return null;
        }
    }

    public static TypeFactory getTypeFactory() {
        return getObjectMapper().getTypeFactory();
    }

    public static <T> T toObject(Map<String, Object> content, Class<T> valueType) {
        try {
            return getObjectMapper().convertValue(content, valueType);
        } catch (IllegalArgumentException e) {
            log.error("Jackson toObject use STRING with valueType processing error! {}", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(String content, Class<T> valueType) {
        try {
            return getObjectMapper().readValue(content, valueType);
        } catch (JacksonException e) {
            log.error("Jackson json processing error, when to object with value type! {}", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(String content, TypeReference<T> typeReference) {
        try {
            return getObjectMapper().readValue(content, typeReference);
        } catch (JacksonException e) {
            log.error("Jackson toObject use STRING with typeReference processing error! {}", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(String content, JavaType javaType) {
        try {
            return getObjectMapper().readValue(content, javaType);
        } catch (JacksonException e) {
            log.error("Jackson toObject use STRING with javaType processing error! {}", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(byte[] bytes, Class<T> valueType) {
        try {
            return getObjectMapper().readValue(bytes, valueType);
        } catch (JacksonException e) {
            log.error("Jackson toObject use BYTE_ARRAY with class processing catch IO error {}.", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(byte[] bytes, TypeReference<T> typeReference) {
        try {
            return getObjectMapper().readValue(bytes, typeReference);
        } catch (JacksonException e) {
            log.error("Jackson toObject use BYTE_ARRAY with typeReference processing catch IO error {}.", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(byte[] bytes, JavaType javaType) {
        try {
            return getObjectMapper().readValue(bytes, javaType);
        } catch (JacksonException e) {
            log.error("Jackson toObject use BYTE_ARRAY with javaType processing catch IO error {}.", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(InputStream inputStream, Class<T> valueType) {
        try {
            return getObjectMapper().readValue(inputStream, valueType);
        } catch (JacksonException e) {
            log.error("Jackson toObject use INPUT_STREAM with class processing catch IO error {}.", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(InputStream inputStream, TypeReference<T> typeReference) {
        try {
            return getObjectMapper().readValue(inputStream, typeReference);
        } catch (JacksonException e) {
            log.error("Jackson toObject use INPUT_STREAM with typeReference processing catch IO error {}.", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(InputStream inputStream, JavaType javaType) {
        try {
            return getObjectMapper().readValue(inputStream, javaType);
        } catch (JacksonException e) {
            log.error("Jackson toObject use INPUT_STREAM with javaType processing catch IO error {}.", e.getMessage());
            return null;
        }
    }

    public static <T> T toObject(JsonNode jsonNode, Class<T> valueType) {
        return getObjectMapper().convertValue(jsonNode, valueType);
    }

    public static <T> T toObject(JsonNode jsonNode, TypeReference<T> typeReference) {
        return getObjectMapper().convertValue(jsonNode, typeReference);
    }

    public static <T> T toObject(JsonNode jsonNode, JavaType javaType) {
        return getObjectMapper().convertValue(jsonNode, javaType);
    }

    public static <T> List<T> toList(String content, Class<T> clazz) {
        JavaType javaType = getObjectMapper().getTypeFactory().constructParametricType(List.class, clazz);
        return toObject(content, javaType);
    }

    public static <K, V> Map<K, V> toMap(String content, Class<K> keyClass, Class<V> valueClass) {
        JavaType javaType = getObjectMapper().getTypeFactory().constructMapType(Map.class, keyClass, valueClass);
        return toObject(content, javaType);
    }

    public static Map<String, Object> toMap(String content) {
        return toMap(content, String.class, Object.class);
    }

    public static <T> Set<T> toSet(String content, Class<T> clazz) {
        JavaType javaType = getTypeFactory().constructCollectionLikeType(Set.class, clazz);
        return toObject(content, javaType);
    }

    public static <T> T[] toArray(String content, Class<T> clazz) {
        JavaType javaType = getTypeFactory().constructArrayType(clazz);
        return toObject(content, javaType);
    }

    public static <T> T[] toArray(String content) {
        return toObject(content, new TypeReference<>() {
        });
    }

    public static JsonNode toNode(String content) {
        try {
            return getObjectMapper().readTree(content);
        } catch (JacksonException e) {
            log.error("Jackson toNode use STRING processing catch json error {}.", e.getMessage());
            return null;
        }
    }

    public static JsonNode toNode(byte[] bytes) {
        try {
            return getObjectMapper().readTree(bytes);
        } catch (JacksonException e) {
            log.error("Jackson toNode use STRING processing catch io error {}.", e.getMessage());
            return null;
        }
    }

    public static JsonNode toNode(JsonParser jsonParser) {
        try {
            return getObjectMapper().readTree(jsonParser);
        } catch (JacksonException e) {
            log.error("Jackson toNode use JsonParser processing catch io error {}.", e.getMessage());
            return null;
        }
    }

    public static JsonParser createParser(String content) {
        try {
            return getObjectMapper().createParser(content);
        } catch (JacksonException e) {
            log.error("Jackson io error, when create parser! {}", e.getMessage());
            return null;
        }
    }

    public static <R> R loop(JsonNode jsonNode, Function<JsonNode, R> function) {

        if (jsonNode.isObject()) {
            Set<Map.Entry<String, JsonNode>> it = jsonNode.properties();

            for (Map.Entry<String, JsonNode> entry : it) {
                loop(entry.getValue(), function);
            }
        }

        if (jsonNode.isArray()) {
            for (JsonNode node : jsonNode) {
                loop(node, function);
            }
        }

        if (jsonNode.isValueNode()) {
            return function.apply(jsonNode);
        } else {
            return null;
        }
    }
}
