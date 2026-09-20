/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.junit.Before;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Setting;
import org.opensearch.plugins.Plugin;
import org.opensearch.securityanalytics.logtype.BuiltinLogTypeLoader;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.transport.MockTransportService;

public class LogTypeServiceMetadataTests extends OpenSearchIntegTestCase {

    private LogTypeService logTypeService;

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Arrays.asList(TestPlugin.class, MockTransportService.TestPlugin.class);
    }

    @Before
    public void setup() {
        if (logTypeService == null) {
            BuiltinLogTypeLoader builtinLogTypeLoader = new TestBuiltinLogTypeLoader();
            logTypeService = new LogTypeService(client(), clusterService(), xContentRegistry(), builtinLogTypeLoader);
        }
    }

    public void testGetAllLogTypesMetadataIncludesLogTypesWithAndWithoutMappings()
            throws ExecutionException, InterruptedException {
        ensureGreen();

        PlainActionFuture<List<String>> future = new PlainActionFuture<>();
        logTypeService.getAllLogTypesMetadata(future);
        List<String> logTypes = future.get();

        assertTrue(logTypes.contains("apache_access"));
        assertTrue(logTypes.contains("linux"));
    }

    public void testGetAllLogTypesExcludesLogTypesWithoutMappings()
            throws ExecutionException, InterruptedException {
        ensureGreen();

        PlainActionFuture<List<String>> future = new PlainActionFuture<>();
        logTypeService.getAllLogTypes(future);
        List<String> logTypes = future.get();

        assertFalse(logTypes.contains("apache_access"));
        assertTrue(logTypes.contains("linux"));
    }

    public static class TestPlugin extends Plugin {
        @Override
        public List<Setting<?>> getSettings() {
            return Arrays.asList(SecurityAnalyticsSettings.DEFAULT_MAPPING_SCHEMA);
        }
    }

    private static class TestBuiltinLogTypeLoader extends BuiltinLogTypeLoader {
        private static final String APACHE_ACCESS = "apache_access";
        private static final String LINUX = "linux";

        @Override
        public List<LogType> getAllLogTypes() {
            LogType apacheAccess = new LogType(
                    null,
                    APACHE_ACCESS,
                    "Apache access logs",
                    true,
                    List.of(),
                    List.of()
            );
            LogType linux = new LogType(
                    null,
                    LINUX,
                    "Linux logs",
                    true,
                    List.of(new LogType.Mapping("raw_field", "ecs_field", "ocsf_field", "ocsf11_field")),
                    List.of()
            );
            return List.of(apacheAccess, linux);
        }

        @Override
        protected List<CustomLogType> loadBuiltinLogTypesMetadata() {
            return List.of(
                    new CustomLogType(null, null, APACHE_ACCESS, "Apache access logs", "Other", "Sigma", Map.of()),
                    new CustomLogType(null, null, LINUX, "Linux logs", "Other", "Sigma", Map.of())
            );
        }
    }
}

