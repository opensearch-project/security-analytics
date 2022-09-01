/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
public class MapperFacade {
    private Map<String, String> mapperMap;
    private static MapperFacade mapperFacade;
    public MapperFacade() {
        mapperMap = new HashMap<>();
        mapperMap.put("netflow", "OSMapping/NetFlowMapping.json");
    }

    public static String aliasMappings(String mapperTopic) throws IOException {
        if (mapperFacade == null) {
            mapperFacade = new MapperFacade();
        }
        if (mapperFacade.mapperMap.containsKey(mapperTopic)) {
            return new String(Objects.requireNonNull(

                    mapperFacade.getClass().getClassLoader().getResourceAsStream(mapperFacade.
                            mapperMap.get(mapperTopic))).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
        throw new IllegalArgumentException("Mapper not found-" + mapperTopic);
    }
}
