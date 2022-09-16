/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
public class MapperFacade {
    private Map<String, String> mapperMap;
    private static MapperFacade INSTANCE = new MapperFacade();
    private MapperFacade() {
        mapperMap = new HashMap<>();
        mapperMap.put("netflow", "OSMapping/network/NetFlowMapping.json");
    }

    public static Map<String, String> getAliasMappingsMap() {
        return INSTANCE.mapperMap;
    }

    public static String aliasMappings(String mapperTopic) throws IOException {
        if (INSTANCE.mapperMap.containsKey(mapperTopic)) {
            return new String(Objects.requireNonNull(

                    INSTANCE.getClass().getClassLoader().getResourceAsStream(INSTANCE.
                            mapperMap.get(mapperTopic))).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
        throw new IllegalArgumentException("Mapper not found-" + mapperTopic);
    }

    public static void putAliasMappings(String mapperTopic, String mappingFilePath) throws IOException {
        INSTANCE.mapperMap.put(mapperTopic, mappingFilePath);
    }
}
