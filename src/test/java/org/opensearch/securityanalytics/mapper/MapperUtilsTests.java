/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import com.fasterxml.jackson.core.JsonParseException;
import org.opensearch.cluster.metadata.MappingMetadata;

import org.opensearch.index.mapper.MapperService;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MapperUtilsTests extends OpenSearchTestCase {


    public void testValidateIndexMappingsMissingSome() throws IOException {
        MapperTopicStore.putAliasMappings("test123", "testValidAliasMappingsWithNestedType.json");

        // Create index mappings
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.DestinationPort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        List<String> missingFields = MapperUtils.validateIndexMappings("my_index", mappingMetadata, MapperTopicStore.aliasMappings("test123")).getLeft();
        assertEquals(3, missingFields.size());
    }

    public void testValidateIndexMappingsEmptyMappings() throws IOException {
        MapperTopicStore.putAliasMappings("test123", "testValidAliasMappingsWithNestedType.json");

        // Create index mappings
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, new HashMap<String, Object>());
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> MapperUtils.validateIndexMappings("my_index", mappingMetadata, MapperTopicStore.aliasMappings("test123")));
        assertTrue(e.getMessage().contains("Mappings for index [my_index] are empty"));
    }

    public void testValidateIndexMappingsNoMissing() throws IOException {
        MapperTopicStore.putAliasMappings("test123", "testValidAliasMappingsSimple.json");

        // Create index mappings
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);

        List<String> missingFields = MapperUtils.validateIndexMappings("my_index", mappingMetadata, MapperTopicStore.aliasMappings("test123")).getLeft();
        assertEquals(0, missingFields.size());
    }

    public void testGetAllNonAliasFieldsFromIndex_success() throws IOException {
        // Create index mappings
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("alias_123", Map.of("type", "alias", "path", "netflow.event_data.SourceAddress"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);

        List<String> fields = MapperUtils.getAllNonAliasFieldsFromIndex(mappingMetadata);
        assertEquals(1, fields.size());
        assertEquals("netflow.event_data.SourceAddress", fields.get(0));
    }

    public void testGetAllPathsFromAliasMappingsSuccess() throws IOException {
        MapperTopicStore.putAliasMappings("test123", "testValidAliasMappingsSimple.json");

        List<String> paths = MapperUtils.getAllPathsFromAliasMappings(MapperTopicStore.aliasMappings("test123"));
        assertEquals(1, paths.size());
        assertEquals("netflow.event_data.SourceAddress", paths.get(0));
    }

    public void testGetAllPathsFromAliasMappingsThrow() throws IOException {
        MapperTopicStore.putAliasMappings("test1", "testMissingPath.json");
        MapperTopicStore.putAliasMappings("test2", "testMultipleAliasesWithSameName.json");

        assertThrows(IllegalArgumentException.class, () -> MapperUtils.getAllPathsFromAliasMappings(MapperTopicStore.aliasMappings("test1")));
        assertThrows(JsonParseException.class, () -> MapperUtils.getAllPathsFromAliasMappings(MapperTopicStore.aliasMappings("test2")));
    }
}
