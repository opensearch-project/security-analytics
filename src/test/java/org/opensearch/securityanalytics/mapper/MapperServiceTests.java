
/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import org.opensearch.core.action.ActionListener;
import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.securityanalytics.action.GetMappingsViewResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MapperServiceTests extends OpenSearchTestCase {

    /**
     * Injects a mocked {@link LogTypeService} into the private, setter-less
     * {@code logTypeService} field of a {@link MapperService} instance.
     */
    private static void injectLogTypeService(MapperService mapperService, LogTypeService logTypeService) throws Exception {
        Field field = MapperService.class.getDeclaredField("logTypeService");
        field.setAccessible(true);
        field.set(mapperService, logTypeService);
    }

    /**
     * Stubs {@code indicesClient.getIndex(...)} so that the resolveConcreteIndex
     * call sees an index pattern with zero backing indices (indices() == []).
     */
    private static void stubGetIndexWithZeroBackingIndices(IndicesAdminClient client) {
        GetIndexResponse getIndexResponse = mock(GetIndexResponse.class);
        when(getIndexResponse.indices()).thenReturn(new String[0]);
        doAnswer(invocation -> {
            ActionListener<GetIndexResponse> l = invocation.getArgument(1);
            l.onResponse(getIndexResponse);
            return null;
        }).when(client).getIndex(any(GetIndexRequest.class), any(ActionListener.class));
    }

    /**
     * Stubs {@code indicesClient.getMappings(...)} to return an empty mappings
     * response — mirroring what LENIENT_EXPAND_OPEN yields for a missing index.
     */
    private static void stubGetMappingsEmpty(IndicesAdminClient client) {
        GetMappingsResponse emptyMappings = new GetMappingsResponse(Map.of());
        doAnswer(invocation -> {
            ActionListener<GetMappingsResponse> l = invocation.getArgument(1);
            l.onResponse(emptyMappings);
            return null;
        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));
    }

    /**
     * Regression test for the resolveConcreteIndex zero-backing-indices pass-through.
     *
     * <p>When an index pattern resolves to zero concrete indices, resolveConcreteIndex now
     * passes the pattern name through unchanged (previously it threw IllegalArgumentException).
     * getMappingAction must then return an EMPTY GetIndexMappingsResponse via the isEmpty()
     * guard rather than NPE-ing or invoking onFailure.
     */
    public void testGetMappingAction_zeroBackingIndices_returnsEmptyResponse() throws Exception {
        MapperService mapperService = spy(MapperService.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperService.setIndicesAdminClient(client);

        LogTypeService logTypeService = mock(LogTypeService.class);
        // getMappingAction's onResponse path invokes getRequiredFieldsForAllLogTypes; drive its callback.
        doAnswer(invocation -> {
            ActionListener<Map<String, java.util.Set<String>>> l = invocation.getArgument(0);
            l.onResponse(Map.of());
            return null;
        }).when(logTypeService).getRequiredFieldsForAllLogTypes(any(ActionListener.class));
        injectLogTypeService(mapperService, logTypeService);

        stubGetIndexWithZeroBackingIndices(client);
        stubGetMappingsEmpty(client);

        AtomicReference<GetIndexMappingsResponse> response = new AtomicReference<>();
        AtomicBoolean failed = new AtomicBoolean(false);
        mapperService.getMappingAction("pattern-with-no-indices-*", new ActionListener<>() {
            @Override
            public void onResponse(GetIndexMappingsResponse getIndexMappingsResponse) {
                response.set(getIndexMappingsResponse);
            }

            @Override
            public void onFailure(Exception e) {
                failed.set(true);
            }
        });

        assertFalse("onFailure must not be called for a zero-backing-indices pattern", failed.get());
        assertNotNull("onResponse must be invoked with a response", response.get());
        assertTrue("mappings must be empty for a pattern with no backing indices",
                response.get().getMappings().isEmpty());
    }

    /**
     * Regression test for the resolveConcreteIndex zero-backing-indices pass-through.
     *
     * <p>getMappingsViewAction must return an EMPTY GetMappingsViewResponse (empty alias
     * mappings, empty unmapped lists) via the isEmpty() guard when the index pattern has
     * no backing indices — not NPE and not onFailure.
     */
    public void testGetMappingsViewAction_zeroBackingIndices_returnsEmptyResponse() throws Exception {
        MapperService mapperService = spy(MapperService.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperService.setIndicesAdminClient(client);

        LogTypeService logTypeService = mock(LogTypeService.class);
        // The view path calls getRequiredFields(...) and getIocFieldsList(...).
        doAnswer(invocation -> {
            ActionListener<List<org.opensearch.securityanalytics.model.LogType.Mapping>> l = invocation.getArgument(1);
            l.onResponse(List.of());
            return null;
        }).when(logTypeService).getRequiredFields(anyString(), any(ActionListener.class));
        when(logTypeService.getIocFieldsList(anyString())).thenReturn(List.of());
        injectLogTypeService(mapperService, logTypeService);

        stubGetIndexWithZeroBackingIndices(client);
        stubGetMappingsEmpty(client);

        AtomicReference<GetMappingsViewResponse> response = new AtomicReference<>();
        AtomicBoolean failed = new AtomicBoolean(false);
        mapperService.getMappingsViewAction("pattern-with-no-indices-*", "test_windows", new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsViewResponse getMappingsViewResponse) {
                response.set(getMappingsViewResponse);
            }

            @Override
            public void onFailure(Exception e) {
                failed.set(true);
            }
        });

        assertFalse("onFailure must not be called for a zero-backing-indices pattern", failed.get());
        assertNotNull("onResponse must be invoked with a response", response.get());
        assertTrue("alias mappings must be empty for a pattern with no backing indices",
                response.get().getAliasMappings().isEmpty());
        assertTrue("unmapped index fields must be empty",
                response.get().getUnmappedIndexFields().isEmpty());
        assertTrue("unmapped field aliases must be empty",
                response.get().getUnmappedFieldAliases().isEmpty());
    }

//    public void testCreateMappingAction_pathIsNull() throws IOException {
//        MapperTopicStore.putAliasMappings("test", "testMissingPath.json");
//
//        MapperService mapperService = spy(MapperService.class);
//        IndicesAdminClient client = mock(IndicesAdminClient.class);
//        mapperService.setIndicesAdminClient(client);
//        // Create fake GetIndexMappingsResponse
//        Map<String, MappingMetadata> mappings = new HashMap<>();
//        Map<String, Object> m = new HashMap<>();
//        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
//        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
//        Map<String, Object> properties = Map.of("properties", m);
//        Map<String, Object> root = Map.of(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, properties);
//        MappingMetadata mappingMetadata = new MappingMetadata(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, root);
//        mappings.put("my_index", mappingMetadata);
//        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings);
//        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
//        doAnswer(invocation -> {
//            ActionListener l = invocation.getArgument(1);
//            l.onResponse(getMappingsResponse);
//            return null;
//        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));
//
//        // Call CreateMappingAction
//        mapperService.createMappingAction("my_index", "test", false, new ActionListener<AcknowledgedResponse>() {
//            @Override
//            public void onResponse(AcknowledgedResponse acknowledgedResponse) {
//
//            }
//
//            @Override
//            public void onFailure(Exception e) {
//                assertTrue(e instanceof SecurityAnalyticsException);
//                assertTrue(e.getCause().getMessage().equals("Alias mappings are missing path for alias: [srcport]"));
//            }
//        });
//    }
//
//    public void testCreateMappingAction_multipleAliasesWithSameName() {
//        // We expect JSON parser to throw "duplicate fields" error
//
//        // Setup
//        MapperTopicStore.putAliasMappings("test1", "testMultipleAliasesWithSameName.json");
//        MapperService mapperService = spy(MapperService.class);
//        IndicesAdminClient client = mock(IndicesAdminClient.class);
//        mapperService.setIndicesAdminClient(client);
//        // Create fake GetIndexMappingsResponse
//        Map<String, MappingMetadata> mappings = new HashMap<>();
//        Map<String, Object> m = new HashMap<>();
//
//        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
//        m.put("netflow.event_data.DestinationPort", Map.of("type", "integer"));
//        Map<String, Object> properties = Map.of("properties", m);
//        Map<String, Object> root = Map.of(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, properties);
//        MappingMetadata mappingMetadata = new MappingMetadata(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, root);
//        mappings.put("my_index", mappingMetadata);
//        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings);
//        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
//        doAnswer(invocation -> {
//            ActionListener l = invocation.getArgument(1);
//            l.onResponse(getMappingsResponse);
//            return null;
//        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));
//
//        // Call CreateMappingAction
//        mapperService.createMappingAction("my_index", "test1", false, new ActionListener<AcknowledgedResponse>() {
//            @Override
//            public void onResponse(AcknowledgedResponse acknowledgedResponse) {
//
//            }
//
//            @Override
//            public void onFailure(Exception e) {
//                assertTrue(e instanceof SecurityAnalyticsException);
//                assertTrue(e.getCause().getMessage().contains("Duplicate field 'srcaddr'"));
//            }
//        });
//    }

/*    public void testGetMappingsView_successAliasesOnlyReturned() {
        // We expect JSON parser to throw "duplicate fields" error

        // Setup
        MapperTopicStore.putAliasMappings("test1", "testValidAliasMappings.json");
        MapperService mapperService = spy(MapperService.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperService.setIndicesAdminClient(client);
        // Create fake GetIndexMappingsResponse
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        // all matched fields
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.DestAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.SourcePort", Map.of("type", "integer"));
        m.put("netflow.event_data.DestinationPort", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings);
        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(1);
            l.onResponse(getMappingsResponse);
            return null;
        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));

        // Call getMappingsViewAction
        mapperService.getMappingsViewAction("my_index", "test1", new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsViewResponse getMappingsViewResponse) {
                // Verify matched alias mappings
                Map<String, Object> props =
                        (Map<String, Object>) getMappingsViewResponse.getAliasMappings().get("properties");
                assertEquals(4, props.size());
                assertTrue(props.containsKey("srcaddr"));
                assertTrue(props.containsKey("dstport"));
                assertTrue(props.containsKey("dstaddr"));
                assertTrue(props.containsKey("srcport"));
                // Verify 0 unmapped field aliases
                assertEquals(0, getMappingsViewResponse.getUnmappedFieldAliases().size());
                // Verify 0 unmatched index fields
                assertEquals(0, getMappingsViewResponse.getUnmappedIndexFields().size());
            }

            @Override
            public void onFailure(Exception e) {
                fail("Unexpected error: " + e.getMessage());
            }
        });
    }

    public void testGetMappingsView_successAllTypesReturned() {
        // We expect JSON parser to throw "duplicate fields" error

        // Setup
        MapperTopicStore.putAliasMappings("test1", "testValidAliasMappings.json");
        MapperService mapperService = spy(MapperService.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperService.setIndicesAdminClient(client);
        // Create fake GetIndexMappingsResponse
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        // 2 matched fields
        m.put("netflow.event_data.SourceAddress", Map.of("type", "ip"));
        m.put("netflow.event_data.DestinationPort", Map.of("type", "integer"));
        // 2 unmatched fields
        m.put("unmatchedfield1", Map.of("type", "ip"));
        m.put("unmatchedfield2", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings);
        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(1);
            l.onResponse(getMappingsResponse);
            return null;
        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));

        // Call getMappingsViewAction
        mapperService.getMappingsViewAction("my_index", "test1", new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsViewResponse getMappingsViewResponse) {
                // Verify matched alias mappings
                Map<String, Object> props =
                        (Map<String, Object>) getMappingsViewResponse.getAliasMappings().get("properties");
                assertEquals(2, props.size());
                assertTrue(props.containsKey("srcaddr"));
                assertTrue(props.containsKey("dstport"));
                // Verify unmapped field aliases or aliases we didn't find paths in index mappings
                assertEquals(2, getMappingsViewResponse.getUnmappedFieldAliases().size());
                assertEquals("dstaddr", getMappingsViewResponse.getUnmappedFieldAliases().get(0));
                assertEquals("srcport", getMappingsViewResponse.getUnmappedFieldAliases().get(1));
                // Verify unmatched index fields
                assertEquals(2, getMappingsViewResponse.getUnmappedIndexFields().size());
                assertEquals("unmatchedfield1", getMappingsViewResponse.getUnmappedIndexFields().get(0));
                assertEquals("unmatchedfield2", getMappingsViewResponse.getUnmappedIndexFields().get(1));
            }

            @Override
            public void onFailure(Exception e) {
                fail("Unexpected error: " + e.getMessage());
            }
        });
    }

    public void testGetMappingsView_successNoAliasesMatched() {
        // We expect JSON parser to throw "duplicate fields" error

        // Setup
        MapperTopicStore.putAliasMappings("test1", "testValidAliasMappings.json");
        MapperService mapperService = spy(MapperService.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperService.setIndicesAdminClient(client);
        // Create fake GetIndexMappingsResponse
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        // 2 unmatched fields
        m.put("unmatchedfield1", Map.of("type", "ip"));
        m.put("unmatchedfield2", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings);
        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(1);
            l.onResponse(getMappingsResponse);
            return null;
        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));

        // Call getMappingsViewAction
        mapperService.getMappingsViewAction("my_index", "test1", new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsViewResponse getMappingsViewResponse) {
                // Verify matched alias mappings
                Map<String, Object> props =
                        (Map<String, Object>) getMappingsViewResponse.getAliasMappings().get("properties");
                assertEquals(0, props.size());
                // Verify unmapped field aliases or aliases we didn't find paths in index mappings
                assertEquals(4, getMappingsViewResponse.getUnmappedFieldAliases().size());
                assertTrue(getMappingsViewResponse.getUnmappedFieldAliases().contains("srcaddr"));
                assertTrue(getMappingsViewResponse.getUnmappedFieldAliases().contains("dstport"));
                assertTrue(getMappingsViewResponse.getUnmappedFieldAliases().contains("dstaddr"));
                assertTrue(getMappingsViewResponse.getUnmappedFieldAliases().contains("srcport"));
                // Verify unmatched index fields
                assertEquals(2, getMappingsViewResponse.getUnmappedIndexFields().size());
                assertEquals("unmatchedfield1", getMappingsViewResponse.getUnmappedIndexFields().get(0));
                assertEquals("unmatchedfield2", getMappingsViewResponse.getUnmappedIndexFields().get(1));
            }

            @Override
            public void onFailure(Exception e) {
                fail("Unexpected error: " + e.getMessage());
            }
        });
    }

    public void testGetMappingsView_failureIncorrectTopic() {
        // Setup
        MapperService mapperService = spy(MapperService.class);
        IndicesAdminClient client = mock(IndicesAdminClient.class);
        mapperService.setIndicesAdminClient(client);
        // Create fake GetIndexMappingsResponse
        Map<String, MappingMetadata> mappings = new HashMap<>();
        Map<String, Object> m = new HashMap<>();
        // 2 unmatched fields
        m.put("unmatchedfield1", Map.of("type", "ip"));
        m.put("unmatchedfield2", Map.of("type", "integer"));
        Map<String, Object> properties = Map.of("properties", m);
        Map<String, Object> root = Map.of(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, properties);
        MappingMetadata mappingMetadata = new MappingMetadata(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, root);
        mappings.put("my_index", mappingMetadata);
        GetMappingsResponse getMappingsResponse = new GetMappingsResponse(mappings);
        // Setup getMappings interceptor and return fake GetMappingsResponse by calling listener.onResponse
        doAnswer(invocation -> {
            ActionListener l = invocation.getArgument(1);
            l.onResponse(getMappingsResponse);
            return null;
        }).when(client).getMappings(any(GetMappingsRequest.class), any(ActionListener.class));

        // Call getMappingsViewAction
        mapperService.getMappingsViewAction("my_index", "incorrectTopicName", new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsViewResponse getMappingsViewResponse) {
                fail("Unexpected onResponse call");
            }

            @Override
            public void onFailure(Exception e) {
                assertTrue(e.getMessage().contains("Mapper not found: [incorrectTopicName]"));
            }
        });
    }*/

}
