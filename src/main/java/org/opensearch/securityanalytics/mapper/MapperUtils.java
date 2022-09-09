package org.opensearch.securityanalytics.mapper;

import org.opensearch.common.xcontent.DeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class MapperUtils {

    public static final String PROPERTIES = "properties";
    public static final String PATH = "path";
    public static final String TYPE = "type";
    public static final String ALIAS = "alias";
    public static final String NESTED = "nested";

    public static List<String> getAllPathsFromAliasMappings(String aliasMappingsJson) throws IOException {
        List<String> paths = new ArrayList<>();
        try (
                XContentParser parser = JsonXContent.jsonXContent
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                aliasMappingsJson)
        ) {
            Map<String, Map<String, Object>> properties = (Map<String, Map<String, Object>>) parser.map().get("properties");
            properties.forEach((k, v) -> {
                if (v.containsKey(PATH)) {
                    paths.add((String) v.get(PATH));
                } else if (v.containsKey(TYPE) && v.get(TYPE).equals(NESTED)) {
                    Map<String, Object> props = (Map<String, Object>) v.get(PROPERTIES);
                    if (props.size() > 0) {
                        props = (Map<String, Object>) props.entrySet().iterator().next().getValue();
                        if (props.containsKey(PATH)) {
                            paths.add((String) props.get(PATH));
                        }
                    }
                }
            });
        }
        return paths;
    }

}
