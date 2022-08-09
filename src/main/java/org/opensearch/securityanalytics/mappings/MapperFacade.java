package org.opensearch.securityanalytics.mappings;
import java.io.File;
import java.io.FileInputStream;
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
        mapperMap.put("macos", "OSMapping/macos/mappings.json");
    }
/*
    public static String getJsonString(String mapperTopic) throws IOException {
        String jsonPath = aliasMappings(mapperTopic);
        File file = new File(jsonPath);
        FileInputStream fileInputStream = new FileInputStream(file);

        retrun
    }
*/
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
