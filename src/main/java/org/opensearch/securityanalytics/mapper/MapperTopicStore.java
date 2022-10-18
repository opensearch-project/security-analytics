/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchParseException;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;

public class MapperTopicStore {

    private static final String MAPPER_CONFIG_FILE = "OSMapping/mapper_topics.json";

    private static final Logger log = LogManager.getLogger(MapperTopicStore.class);

    private Map<String, String> mapperMap;
    private static MapperTopicStore INSTANCE = new MapperTopicStore();
    private MapperTopicStore() {

        String mapperTopicsJson;
        try (
                InputStream is = MapperTopicStore.class.getClassLoader().getResourceAsStream(MAPPER_CONFIG_FILE)
        ) {
            mapperMap = new HashMap<>();
            mapperTopicsJson = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);

            if (mapperTopicsJson != null) {
                Map<String, Object> configMap =
                        XContentHelper.convertToMap(JsonXContent.jsonXContent, mapperTopicsJson, false);

                mapperMap = configMap.entrySet()
                        .stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().toString()));

                log.info("Loaded {} mapper topics", mapperMap.size());
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
