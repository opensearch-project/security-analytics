/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Setting;
import org.opensearch.plugins.Plugin;
import org.opensearch.securityanalytics.logtype.BuiltinLogTypeLoader;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.FieldMappingDoc;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.transport.MockTransportService;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.opensearch.securityanalytics.logtype.LogTypeService.LOG_TYPE_INDEX;

public class LogTypeServiceTests extends OpenSearchIntegTestCase {

    private LogTypeService logTypeService;


    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Arrays.asList(TestPlugin.class, MockTransportService.TestPlugin.class);
    }

    @Before
    protected void beforeTest() throws Exception {
        if (logTypeService == null) {
            BuiltinLogTypeLoader builtinLogTypeLoader = mock(BuiltinLogTypeLoader.class);
            doNothing().when(builtinLogTypeLoader).ensureLogTypesLoaded();

            List<LogType> dummyLogTypes = List.of(
                new LogType(null, "test_logtype", "", true,
                        List.of(
                                new LogType.Mapping("rawFld1", "ecsFld1", "ocsfFld1"),
                                new LogType.Mapping("rawFld2", "ecsFld2", "ocsfFld2"),
                                new LogType.Mapping("rawFld3", "ecsFld3", "ocsfFld3")
                        )
                )
            );
            when(builtinLogTypeLoader.getAllLogTypes()).thenReturn(dummyLogTypes);
            logTypeService = new LogTypeService(client(), clusterService(), xContentRegistry(), builtinLogTypeLoader);
        }
    }

    public void testIndexMappings() throws ExecutionException, InterruptedException {
        ensureGreen();

        List<FieldMappingDoc> fieldMappingDocs = List.of(
            new FieldMappingDoc("fld1", Map.of("ecs", "ecs_fld1", "ocsf", "ocsf_fld1"), Set.of("windows")),
            new FieldMappingDoc("fld2", Map.of("ecs", "ecs_fld2", "ocsf", "ocsf_fld2"), Set.of("windows")),
            new FieldMappingDoc("fld3", Map.of("ecs", "ecs_winlog.fld3", "ocsf", "ocsf_fld3"), Set.of("windows"))
        );

        indexFieldMappings(fieldMappingDocs);

        client().admin().indices().refresh(new RefreshRequest(LOG_TYPE_INDEX)).get();

        fieldMappingDocs = List.of(
                new FieldMappingDoc("fld1", Map.of("ecs", "ecs_fld1", "ocsf", "ocsf_fld111"), Set.of("linux")),
                new FieldMappingDoc("fld2", Map.of("ecs", "ecs_fld2", "ocsf", "ocsf_fld222"), Set.of("linux")),
                new FieldMappingDoc("fld3", Map.of("ecs", "network.something", "ocsf", "ocsf_fld333"), Set.of("network"))
        );

        indexFieldMappings(fieldMappingDocs);

        client().admin().indices().refresh(new RefreshRequest(LOG_TYPE_INDEX)).get();

        PlainActionFuture<List<FieldMappingDoc>> getAllFieldMappingsFuture = new PlainActionFuture<>();
        logTypeService.getAllFieldMappings(getAllFieldMappingsFuture);
        try {
            List<FieldMappingDoc> allFieldMappings = getAllFieldMappingsFuture.get();
            // 3 initial ones from test_logtype, fld1 and fld2 are inserted and then updated/merged and fld3 is inserted twice since ecs field is different
            assertEquals(7, allFieldMappings.size());
        } catch (Exception e) {
            fail(e.getMessage());
        }


        List<String> allLogTypes = getAllLogTypes();
        assertEquals(4, allLogTypes.size());
        assertTrue(allLogTypes.contains("windows"));
        assertTrue(allLogTypes.contains("linux"));
        assertTrue(allLogTypes.contains("test_logtype"));
        assertTrue(allLogTypes.contains("network"));

        List<FieldMappingDoc> fieldMappings =  getFieldMappingsByLogTypes(List.of("linux"));
        assertEquals(2, fieldMappings.size());
        fieldMappings =  getFieldMappingsByLogTypes(List.of("windows"));
        assertEquals(3, fieldMappings.size());

    }

    public void testSetLogTypeMappingSchema() {
        int expectedVersion = 2;
        int version = logTypeService.logTypeMappingVersion;
        assertEquals(expectedVersion, version);
    }

    private void indexFieldMappings(List<FieldMappingDoc> fieldMappingDocs) {
        PlainActionFuture<Void> fut = new PlainActionFuture<>();

        logTypeService.indexFieldMappings(fieldMappingDocs, fut);
        try {
            fut.get();
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    private List<FieldMappingDoc> getFieldMappingsByLogTypes(List<String> logTypes) {
        PlainActionFuture<List<FieldMappingDoc>> future = new PlainActionFuture<>();
        logTypeService.getFieldMappingsByLogTypes(logTypes, future);
        try {
            return future.get();
        } catch (Exception e) {
            fail(e.getMessage());
        }
        return null;
    }

    private List<String> getAllLogTypes() {
        PlainActionFuture<List<String>> getAllLogTypesFuture = new PlainActionFuture<>();
        logTypeService.getAllLogTypes(getAllLogTypesFuture);
        try {
            return getAllLogTypesFuture.get();
        } catch (Exception e) {
            fail(e.getMessage());
        }
        return null;
    }

    public static class TestPlugin extends Plugin {
        @Override
        public List<Setting<?>> getSettings() {
            return Arrays.asList(SecurityAnalyticsSettings.DEFAULT_MAPPING_SCHEMA);
        }
    }

}
