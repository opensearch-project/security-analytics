package org.opensearch.securityanalytics.mapper;

import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.xcontent.DeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class MapperUtils {

    public static final String PROPERTIES = "properties";
    public static final String PATH = "path";
    public static final String TYPE = "type";
    public static final String ALIAS = "alias";
    public static final String NESTED = "nested";

    public static List<String> getAllPathsFromAliasMappings(String aliasMappingsJson) throws IOException {
        List<String> paths = new ArrayList<>();

        MappingsTraverser mappingsTraverser = new MappingsTraverser(aliasMappingsJson, Set.of());
        mappingsTraverser.addListener((node, properties, fullPath) -> {
            if (properties.containsKey(PATH) == false) {
                throw new IllegalArgumentException("Alias mappings are missing path for alias: [" + node.getNodeName() + "]");
            }
            if (properties.get(TYPE).equals(ALIAS) == false) {
                throw new IllegalArgumentException("Alias mappings contains property of type: [" + node.node.get(TYPE) + "]");
            }
            paths.add((String) properties.get(PATH));
        });
        mappingsTraverser.traverse();
        return paths;
    }

    /**
     * Checks if index's mappings contain all paths we want to apply alias to.
     * Returnes list of missing paths in index mappings
     * */
    public static List<String> validateIndexMappings(ImmutableOpenMap<String, MappingMetadata> indexMappings, String ruleTopic) throws IOException {
        List<String> missingFieldsInIndexMappings = new ArrayList<>();

        String aliasMappings = MapperFacade.aliasMappings(ruleTopic);
        // Get all paths (field names) to which we're going to apply aliases
        List<String> paths = getAllPathsFromAliasMappings(aliasMappings);

        String indexName = indexMappings.iterator().next().key;
        MappingMetadata mappingMetadata = indexMappings.get(indexName);
        // Check if index's mapping is empty
        Map<String, Object> map = mappingMetadata.getSourceAsMap();
        if (map.size() == 0) {
            missingFieldsInIndexMappings.addAll(paths);
            return missingFieldsInIndexMappings;
        }

        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);

        List<String> flatFields = mappingsTraverser.extractFlatNonAliasFields();

        return paths.stream()
                .filter(e -> !flatFields.contains(e))
                .collect(Collectors.toList());
    }

}
