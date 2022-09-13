/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.mapper.model.GetIndexMappingsResponse;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.any;

public class MapperApplierTests extends OpenSearchTestCase {

    public void testPathIsNull() throws IOException {
        MapperFacade.putAliasMappings("test", "testMissingPath.json");

        MapperApplier mapperApplier = spy(MapperApplier.class);

        // Create fake GetIndexMappingsResponse
        ImmutableOpenMap.Builder<String, MappingMetadata> mappings = ImmutableOpenMap.builder();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetIndexMappingsResponse getIndexMappingsResponse = new GetIndexMappingsResponse(mappings.build());
        // Setup getMappingAction interceptor and return fake GetIndexMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = (ActionListener) invocation.getArgument(1);
            l.onResponse(getIndexMappingsResponse);
            return null;
        }).when(mapperApplier).getMappingAction(anyString(), any(ActionListener.class));

        // Call CreateMappingAction
        mapperApplier.createMappingAction("my_index", "test", new ActionListener<AcknowledgedResponse>() {
            @Override
            public void onResponse(AcknowledgedResponse acknowledgedResponse) {

            }

            @Override
            public void onFailure(Exception e) {
                assertTrue(e.getMessage().equals("Alias mappings are missing path for alias: [srcport]"));
            }
        });
    }

    public void testMultipleAliasesWithSameName() throws IOException {
        // We expect JSON parser to throw "duplicate fields" error

        MapperFacade.putAliasMappings("test1", "testMultipleAliasesWithSameName.json");

        MapperApplier mapperApplier = spy(MapperApplier.class);

        // Create fake GetIndexMappingsResponse
        ImmutableOpenMap.Builder<String, MappingMetadata> mappings = ImmutableOpenMap.builder();
        Map<String, Object> m = new HashMap<>();

        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.DestinationPort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetIndexMappingsResponse getIndexMappingsResponse = new GetIndexMappingsResponse(mappings.build());
        // Setup getMappingAction interceptor and return fake GetIndexMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = (ActionListener) invocation.getArgument(1);
            l.onResponse(getIndexMappingsResponse);
            return null;
        }).when(mapperApplier).getMappingAction(anyString(), any(ActionListener.class));

        // Call CreateMappingAction
        mapperApplier.createMappingAction("my_index", "test1", new ActionListener<AcknowledgedResponse>() {
            @Override
            public void onResponse(AcknowledgedResponse acknowledgedResponse) {

            }

            @Override
            public void onFailure(Exception e) {
                assertTrue(e.getMessage().contains("Duplicate field 'srcaddr'"));
            }
        });
    }

}
