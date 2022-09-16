
/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.IndicesAdminClient;
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
import static org.mockito.Mockito.mock;

public class MapperApplierTests extends OpenSearchTestCase {

    public void testPathIsNull() throws IOException {
        MapperFacade.putAliasMappings("test", "testMissingPath.json");

        MapperApplier mapperApplier = spy(MapperApplier.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperApplier.setIndicesAdminClient(client);
        // Create fake GetIndexMappingsResponse
        ImmutableOpenMap.Builder<String, MappingMetadata> mappings = ImmutableOpenMap.builder();
        Map<String, Object> m = new HashMap<>();
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings.build());
        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(1);
            l.onResponse(getMappingsResponse);
            return null;
        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));

        // Call CreateMappingAction
        mapperApplier.createMappingAction("my_index", "test", false, new ActionListener<AcknowledgedResponse>() {
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

        // Setup
        MapperFacade.putAliasMappings("test1", "testMultipleAliasesWithSameName.json");
        MapperApplier mapperApplier = spy(MapperApplier.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperApplier.setIndicesAdminClient(client);
        // Create fake GetIndexMappingsResponse
        ImmutableOpenMap.Builder<String, MappingMetadata> mappings = ImmutableOpenMap.builder();
        Map<String, Object> m = new HashMap<>();

        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.DestinationPort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings.build());
        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(1);
            l.onResponse(getMappingsResponse);
            return null;
        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));

        // Call CreateMappingAction
        mapperApplier.createMappingAction("my_index", "test1", false, new ActionListener<AcknowledgedResponse>() {
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
