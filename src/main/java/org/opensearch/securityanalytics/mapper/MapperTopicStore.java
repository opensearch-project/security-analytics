/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
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

    }

    public static String aliasMappings(String mapperTopic) throws IOException {

        if (INSTANCE.mapperMap.containsKey(mapperTopic.toLowerCase(Locale.ROOT))) {
            return new String(Objects.requireNonNull(

                    INSTANCE.getClass().getClassLoader().getResourceAsStream(INSTANCE.
                            mapperMap.get(mapperTopic.toLowerCase(Locale.ROOT)))).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
        throw new IllegalArgumentException("Mapper not found: [" + mapperTopic + "]");
    }

    public static void putAliasMappings(String mapperTopic, String mappingFilePath) {
        INSTANCE.mapperMap.put(mapperTopic, mappingFilePath);
    }
}
