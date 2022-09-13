/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import com.fasterxml.jackson.core.JsonParseException;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MapperUtilsTests extends OpenSearchTestCase {


    public void testValidateIndexMappingsMissingSome() throws IOException {
        MapperFacade.putAliasMappings("test123", "testValidAliasMappingsWithNestedType.json");

        // Create index mappings
        ImmutableOpenMap.Builder<String, MappingMetadata> mappings = ImmutableOpenMap.builder();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.DestinationPort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        List<String> missingFields = MapperUtils.validateIndexMappings(mappings.build(), "test123");
        assertEquals(3, missingFields.size());
    }

    public void testValidateIndexMappingsEmptyMappings() throws IOException {
        MapperFacade.putAliasMappings("test123", "testValidAliasMappingsWithNestedType.json");

        // Create index mappings
        ImmutableOpenMap.Builder<String, MappingMetadata> mappings = ImmutableOpenMap.builder();
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, new HashMap<String, Object>());
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        List<String> missingFields = MapperUtils.validateIndexMappings(mappings.build(), "test123");
        // Expect 5 missing because our alias mapping has 5 total
        assertEquals(5, missingFields.size());
    }

    public void testValidateIndexMappingsNoMissing() throws IOException {
        MapperFacade.putAliasMappings("test123", "testValidAliasMappingsSimple.json");

        // Create index mappings
        ImmutableOpenMap.Builder<String, MappingMetadata> mappings = ImmutableOpenMap.builder();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        List<String> missingFields = MapperUtils.validateIndexMappings(mappings.build(), "test123");
        assertEquals(0, missingFields.size());
    }

    public void testGetAllPathsFromAliasMappingsSuccess() throws IOException {
        MapperFacade.putAliasMappings("test123", "testValidAliasMappingsSimple.json");

        List<String> paths = MapperUtils.getAllPathsFromAliasMappings(MapperFacade.aliasMappings("test123"));
        assertEquals(1, paths.size());
        assertEquals("netflow.event_data.SourceAddress", paths.get(0));
    }

    public void testGetAllPathsFromAliasMappingsThrow() throws IOException {
        MapperFacade.putAliasMappings("test1", "testMissingPath.json");
        MapperFacade.putAliasMappings("test2", "testMultipleAliasesWithSameName.json");

        assertThrows(IllegalArgumentException.class, () -> MapperUtils.getAllPathsFromAliasMappings(MapperFacade.aliasMappings("test1")));
        assertThrows(JsonParseException.class, () -> MapperUtils.getAllPathsFromAliasMappings(MapperFacade.aliasMappings("test2")));
    }
}
