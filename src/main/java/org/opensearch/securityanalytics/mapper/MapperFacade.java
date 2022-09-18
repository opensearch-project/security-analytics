/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import org.opensearch.OpenSearchParseException;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class MapperFacade {

    private static final String MAPPER_CONFIG_FILE = "OSMapping/mapper_topics.json";

    private Map<String, String> mapperMap;
    private static MapperFacade INSTANCE = new MapperFacade();
    private MapperFacade() {

        String mapperTopicsJson;
        try (
                InputStream is = MapperFacade.class.getClassLoader().getResourceAsStream(MAPPER_CONFIG_FILE)
        ) {
            mapperMap = new HashMap<>();
            mapperTopicsJson = new String(Objects.requireNonNull(is).readAllBytes());

            if (mapperTopicsJson != null) {
                Map<String, Object> configMap =
                        XContentHelper.convertToMap(JsonXContent.jsonXContent, mapperTopicsJson, false);

                mapperMap = configMap.entrySet()
                        .stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().toString()));
            }
        } catch (OpenSearchParseException e) {
            throw e;
        } catch (Exception e) {
            throw new SettingsException("Failed to load settings from [" + MAPPER_CONFIG_FILE + "]", e);
        }
    }

    public static String aliasMappings(String mapperTopic) throws IOException {
        if (INSTANCE.mapperMap.containsKey(mapperTopic)) {
            return new String(Objects.requireNonNull(

                    INSTANCE.getClass().getClassLoader().getResourceAsStream(INSTANCE.
                            mapperMap.get(mapperTopic))).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
        throw new IllegalArgumentException("Mapper not found: [" + mapperTopic + "]");
    }

    public static void putAliasMappings(String mapperTopic, String mappingFilePath) {
        INSTANCE.mapperMap.put(mapperTopic, mappingFilePath);
    }

    public static Map<String, String> getAliasMappingsMap() {
        return INSTANCE.mapperMap;
    }
}
