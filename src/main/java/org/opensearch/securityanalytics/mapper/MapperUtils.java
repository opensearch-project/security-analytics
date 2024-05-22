/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class MapperUtils {

    public static final String PROPERTIES = "properties";
    public static final String PATH = "path";
    public static final String TYPE = "type";
    public static final String ALIAS = "alias";
    public static final String NESTED = "nested";

    public static List<String> getAllAliases(String aliasMappingsJson) throws IOException {
        MappingsTraverser mappingsTraverser = new MappingsTraverser(aliasMappingsJson, Set.of());
        List<String> aliasFields = new ArrayList<>();
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                // We'll ignore any irregularities in alias mappings here
                if (node.getProperties().containsKey(PATH) == false ||
                        node.getProperties().get(TYPE).equals(ALIAS) == false) {
                    return;
                }
                aliasFields.add(node.currentPath);
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException(error);
            }
        });
        mappingsTraverser.traverse();
        return aliasFields;
    }

    public static List<Pair<String, String>> getAllAliasPathPairs(String aliasMappingsJson) throws IOException {
        MappingsTraverser mappingsTraverser = new MappingsTraverser(aliasMappingsJson, Set.of());
        return getAllAliasPathPairs(mappingsTraverser);
    }

    public static List<Pair<String, String>> getAllAliasPathPairs(MappingMetadata mappingMetadata) throws IOException {
        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
        return getAllAliasPathPairs(mappingsTraverser);
    }

    public static List<Pair<String, String>> getAllAliasPathPairs(MappingsTraverser mappingsTraverser) throws IOException {
        List<Pair<String, String>> aliasPathPairs = new ArrayList<>();
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                // We'll ignore any irregularities in alias mappings here
                if (node.getProperties().containsKey(PATH) == false ||
                        node.getProperties().get(TYPE).equals(ALIAS) == false) {
                    return;
                }
                aliasPathPairs.add(Pair.of(node.currentPath, (String) node.getProperties().get(PATH)));
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException(error);
            }
        });
        mappingsTraverser.traverse();
        return aliasPathPairs;
    }

    public static List<String> getAllPathsFromAliasMappings(String aliasMappingsJson) throws IOException {
        List<String> paths = new ArrayList<>();

        MappingsTraverser mappingsTraverser = new MappingsTraverser(aliasMappingsJson, Set.of());
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                if (node.getProperties().containsKey(PATH) == false) {
                    throw new IllegalArgumentException("Alias mappings are missing path for alias: [" + node.getNodeName() + "]");
                }
                if (node.getProperties().get(TYPE).equals(ALIAS) == false) {
                    throw new IllegalArgumentException("Alias mappings contains property of type: [" + node.node.get(TYPE) + "]");
                }
                paths.add((String) node.getProperties().get(PATH));
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException(error);
            }
        });
        mappingsTraverser.traverse();
        return paths;
    }

    /**
     * Does following validations:
     * <ul>
     *   <li>Index mappings cannot be empty
     *   <li>Alias mappings have to have property type=alias and path property has to exist
     *   <li>Paths from alias mappings should exists in index mappings
     * </ul>
     * @param indexName Source index name
     * @param mappingMetadata Source index mapping to which alias mappings will be applied
     * @param aliasMappingsJSON Alias mappings as JSON string
     * @return Pair of list of alias mappings paths which are missing in index mappings and list of
     * */
    public static Pair<List<String>, List<String>> validateIndexMappings(String indexName, MappingMetadata mappingMetadata, String aliasMappingsJSON) throws IOException {
        // Check if index's mapping is empty
        if (isIndexMappingsEmpty(mappingMetadata)) {
            throw new IllegalArgumentException(String.format(Locale.ROOT, "Mappings for index [%s] are empty", indexName));
        }

        // Get all paths (field names) to which we're going to apply aliases
        List<String> paths = getAllPathsFromAliasMappings(aliasMappingsJSON);

        // Traverse Index Mappings and extract all fields(paths)
        List<String> flatFields = getAllNonAliasFieldsFromIndex(mappingMetadata);
        // Return list of paths from Alias Mappings which are missing in Index Mappings
        List<String> missingPaths = new ArrayList<>();
        List<String> presentPaths = new ArrayList<>();
        paths.stream().forEach(e -> {
            if (flatFields.contains(e)) presentPaths.add(e);
            else missingPaths.add(e);
        });
        return Pair.of(missingPaths, presentPaths);
    }

    /**
     * Traverses mappings tree and collects all fields.
     * Nested fields are flattened.
     * @return list of fields in mappings.
     */
    public static List<String> extractAllFieldsFlat(MappingMetadata mappingMetadata) {
        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
        List<String> flatProperties = new ArrayList<>();
        // Setup
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                flatProperties.add(node.currentPath);
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException(error);
            }
        });
        // Do traverse
        mappingsTraverser.traverse();
        return flatProperties;
    }

    public static List<String> extractAllFieldsFlat(Map<String, Object> mappingsMap) {
        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingsMap, Set.of());
        List<String> flatProperties = new ArrayList<>();
        // Setup
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                flatProperties.add(node.currentPath);
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException(error);
            }
        });
        // Do traverse
        mappingsTraverser.traverse();
        return flatProperties;
    }

    public static List<String> getAllNonAliasFieldsFromIndex(MappingMetadata mappingMetadata) {
        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
        return mappingsTraverser.extractFlatNonAliasFields();
    }

    public static boolean isIndexMappingsEmpty(MappingMetadata mappingMetadata) {
        return mappingMetadata.getSourceAsMap().size() == 0;
    }

    public static Map<String, Object> getAliasMappingsWithFilter(
            String aliasMappingsJson,
            List<String> aliasesToInclude) throws IOException {

        // Traverse mappings and do copy with excluded type=alias properties
        MappingsTraverser mappingsTraverser = new MappingsTraverser(aliasMappingsJson, Set.of());
        // Resulting properties after filtering
        Map<String, Object> filteredProperties = new HashMap<>();

        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                // Skip everything except ones in include filter
                if (aliasesToInclude.contains(node.currentPath) == false) {
                    return;
                }
                MappingsTraverser.Node n = node;
                while (n.parent != null) {
                    n = n.parent;
                }
                if (n == null) {
                    n = node;
                }
                filteredProperties.put(n.getNodeName(), n.getProperties());
            }

            @Override
            public void onError(String error) {
                throw new IllegalArgumentException("");
            }
        });
        mappingsTraverser.traverse();
        // Construct filtered mappings with PROPERTIES as root and return them as result
        return Map.of(PROPERTIES, filteredProperties);
    }

    public static Map<String, Object> getFieldMappingsFlat(MappingMetadata mappingMetadata, List<String> fieldPaths) {
        Map<String, Object> presentPathsMappings = new HashMap<>();
        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                if (fieldPaths.contains(node.currentPath)) {
                    presentPathsMappings.put(node.currentPath, node.getProperties());
                }
            }

            @Override
            public void onError(String error) {
                throw SecurityAnalyticsException.wrap(
                        new IllegalArgumentException("Failed traversing index mappings: [" + error + "]")
                );
            }
        });
        mappingsTraverser.traverse();
        return presentPathsMappings;
    }
}
