/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import org.opensearch.cluster.metadata.MappingMetadata;

import org.opensearch.index.mapper.MapperService;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;


public class MappingsTraverserTests extends OpenSearchTestCase {





    public void testTraverseValidMappings() {
        // 1. Parse mappings from MappingMetadata
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                assertNotNull(node);
            }

            @Override
            public void onError(String error) {
                fail("Error happened during traversal of valid mappings!");
            }
        });
        mappingsTraverser.traverse();

        // 2. Parse mappings from Map<String, Object>
        mappingsTraverser = new MappingsTraverser(properties, Set.of());
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                assertNotNull(node);
            }

            @Override
            public void onError(String error) {
                fail("Error happened during traversal of valid mappings!");
            }
        });
        mappingsTraverser.traverse();

        // 3. Parse mappings from Map<String, Object>
        String indexMappingJSON = "{" +
        "    \"properties\": {" +
                "        \"netflow.event_data.SourceAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.DestinationPort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event_data.DestAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.SourcePort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"dns.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"ipx.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"plain1\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"user\":{" +
                "          \"type\":\"nested\"," +
                "            \"properties\":{" +
                "              \"first\":{" +
                "                \"type\":\"text\"," +
                "                  \"fields\":{" +
                "                    \"keyword\":{" +
                "                      \"type\":\"keyword\"," +
                "                      \"ignore_above\":256" +
                                      "}" +
                                    "}" +
                                "}," +
                "              \"last\":{" +
                                  "\"type\":\"text\"," +
                                    "\"fields\":{" +
                "                      \"keyword\":{" +
                "                           \"type\":\"keyword\"," +
                "                           \"ignore_above\":256" +
                                        "}" +
                                    "}" +
                                "}" +
                            "}" +
                        "}" +
                "    }" +
                "}";
        try {
            mappingsTraverser = new MappingsTraverser(indexMappingJSON, Set.of());
        } catch (IOException e) {
            fail("Error instantiating MappingsTraverser with JSON string as mappings");
        }
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                assertNotNull(node);
            }

            @Override
            public void onError(String error) {
                fail("Error happened during traversal of valid mappings!");
            }
        });
        mappingsTraverser.traverse();
    }

    public void testTraverseInvalidMappings() {
        // 1. Parse mappings from MappingMetadata
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("incorrect_properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
        final boolean[] errorHappend = new boolean[1];
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                assertNotNull(node);
            }

            @Override
            public void onError(String error) {
                errorHappend[0] = true;
            }
        });
        mappingsTraverser.traverse();
        assertTrue(errorHappend[0]);
    }

    public void testTraverseValidMappingsWithTypeFilter() {
        // 1. Parse mappings from MappingMetadata
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        MappingsTraverser mappingsTraverser = new MappingsTraverser(properties, Set.of("ip"));

        List<String> paths = new ArrayList<>();
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                paths.add(node.currentPath);
            }

            @Override
            public void onError(String error) {
                fail("Failed traversing valid mappings");
            }
        });
        mappingsTraverser.traverse();
        assertEquals(1, paths.size());
        assertEquals("netflow.event_data.SourcePort", paths.get(0));
    }

    public void testTraverseAndCopyValidMappingsWithTypeFilter() {
        // 1. Parse mappings from MappingMetadata
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        MappingsTraverser mappingsTraverser = new MappingsTraverser(properties, Set.of("ip"));
        // Copy mappings while excluding type=ip
        Map<String, Object> filteredMappings = mappingsTraverser.traverseAndCopyAsFlat();
        // Now traverse filtered mapppings to confirm type=ip is not present
        List<String> paths = new ArrayList<>();
        mappingsTraverser = new MappingsTraverser(filteredMappings, Set.of());
        mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
            @Override
            public void onLeafVisited(MappingsTraverser.Node node) {
                paths.add(node.currentPath);
            }

            @Override
            public void onError(String error) {
                fail("Failed traversing valid mappings");
            }
        });
        mappingsTraverser.traverse();
        assertEquals(1, paths.size());
        assertEquals("netflow.event_data.SourcePort", paths.get(0));
    }

    public void testTraverseAndCopyAsFlatValidNestedMappingsWithTypeFilter() {
        String indexMappingJSON = "{" +
        "    \"properties\": {" +
                "        \"netflow.event_data.SourceAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.DestinationPort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event_data.DestAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.SourcePort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"dns.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"ipx.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"plain1\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"user\":{" +
                "          \"type\":\"nested\"," +
                "            \"properties\":{" +
                "              \"first\":{" +
                "                \"type\":\"text\"," +
                "                  \"fields\":{" +
                "                    \"keyword\":{" +
                "                      \"type\":\"keyword\"," +
                "                      \"ignore_above\":256" +
                                      "}" +
                                    "}" +
                                "}," +
                "              \"last\":{" +
                                  "\"type\":\"text\"," +
                                    "\"fields\":{" +
                "                      \"keyword\":{" +
                "                           \"type\":\"keyword\"," +
                "                           \"ignore_above\":256" +
                                        "}" +
                                    "}" +
                                "}" +
                            "}" +
                        "}" +
                "    }" +
                "}";

        MappingsTraverser mappingsTraverser;
        try {

            mappingsTraverser = new MappingsTraverser(indexMappingJSON, Set.of("ip"));

            // Copy mappings while excluding type=ip
            Map<String, Object> filteredMappings = mappingsTraverser.traverseAndCopyAsFlat();

            // Now traverse filtered mapppings to confirm type=ip is not present
            List<String> paths = new ArrayList<>();
            mappingsTraverser = new MappingsTraverser(filteredMappings, Set.of("integer"));
            mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
                @Override
                public void onLeafVisited(MappingsTraverser.Node node) {
                    paths.add(node.currentPath);
                }

                @Override
                public void onError(String error) {
                    fail("Failed traversing valid mappings");
                }
            });
            mappingsTraverser.traverse();
            assertEquals(2, paths.size());
            assertEquals("user.last", paths.get(0));
            assertEquals("user.first", paths.get(1));

        } catch (IOException e) {
            fail("Error instantiating MappingsTraverser with JSON string as mappings");
        }
    }

    public void testTraverseAndCopyValidNestedMappings() {
        String indexMappingJSON = "{" +
                "    \"properties\": {" +
                "        \"netflow.event_data.SourceAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.DestinationPort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event_data.DestAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.SourcePort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"dns.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"ipx.event.stop\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"plain1\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"user\":{" +
                "          \"type\":\"nested\"," +
                "            \"properties\":{" +
                "              \"first\":{" +
                "                \"type\":\"text\"," +
                "                  \"fields\":{" +
                "                    \"keyword\":{" +
                "                      \"type\":\"keyword\"," +
                "                      \"ignore_above\":256" +
                "}" +
                "}" +
                "}," +
                "              \"last\":{" +
                "\"type\":\"long\"," +
                "\"fields\":{" +
                "                      \"keyword\":{" +
                "                           \"type\":\"keyword\"," +
                "                           \"ignore_above\":256" +
                "}" +
                "}" +
                "}" +
                "}" +
                "}" +
                "    }" +
                "}";

        MappingsTraverser mappingsTraverser;
        try {

            mappingsTraverser = new MappingsTraverser(indexMappingJSON, Set.of("ip"));

            // Copy mappings while excluding type=ip
            Map<String, Object> filteredMappings = mappingsTraverser.traverseAndCopyWithFilter(Set.of("user.first", "user.last"));

            // Now traverse filtered mapppings to confirm type=ip is not present
            List<String> paths = new ArrayList<>();
            mappingsTraverser = new MappingsTraverser(filteredMappings, Set.of("integer"));
            mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
                @Override
                public void onLeafVisited(MappingsTraverser.Node node) {
                    paths.add(node.currentPath);
                }

                @Override
                public void onError(String error) {
                    fail("Failed traversing valid mappings");
                }
            });
            mappingsTraverser.traverse();
            assertEquals(2, paths.size());
            assertEquals("user.last", paths.get(0));
            assertEquals("user.first", paths.get(1));

        } catch (IOException e) {
            fail("Error instantiating MappingsTraverser with JSON string as mappings");
        }
    }
}
