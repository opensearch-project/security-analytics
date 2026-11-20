/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.services.STIX2IOCFeedStore;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collection;
import java.util.List;

/** Tests which index names the plugin registers as its system indices. */
public class SecurityAnalyticsSystemIndexDescriptorsTests extends OpenSearchTestCase {

    private final Collection<SystemIndexDescriptor> descriptors = new SecurityAnalyticsPlugin().getSystemIndexDescriptors(Settings.EMPTY);

    public void testTheIndicesOnlyThePluginReadsAreRegistered() {
        List<String> registered = List.of(
                Detector.DETECTORS_INDEX,
                CorrelationRule.CORRELATION_RULE_INDEX,
                CorrelationIndices.CORRELATION_ALERT_INDEX,
                LogTypeService.LOG_TYPE_INDEX,
                Rule.PRE_PACKAGED_RULES_INDEX,
                ".opensearch-sap-threat-intel",
                ".opensearch-sap-threat-intel-feodo-1700000000000",
                ".opensearch-sap-threat-intel-alerts",
                ".opensearch-sap-threat-intel-alerts-history-2026.11.19-1",
                SecurityAnalyticsPlugin.JOB_INDEX_NAME
        );
        for (String index : registered) {
            assertTrue(index + " is registered", isRegistered(index));
        }
    }

    public void testTheIndicesCallersOrTheDashboardsReadDirectlyAreNotRegistered() {
        List<String> notRegistered = List.of(
                // Read as the caller by the rule APIs
                Rule.CUSTOM_RULES_INDEX,
                // Searched directly by the dashboards as .opensearch-sap-ioc*
                STIX2IOCFeedStore.getNewActiveIndex("Config-Id"),
                ".opensearch-sap-ioc-findings",
                ".opensearch-sap-ioc-findings-history-2026.11.19-1",
                // Read as the caller by the correlation search and list APIs
                CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX,
                ".opensearch-sap-correlation-history-2026.11.19-1",
                CorrelationIndices.CORRELATION_METADATA_INDEX
        );
        for (String index : notRegistered) {
            assertFalse(index + " is not registered", isRegistered(index));
        }
    }

    public void testLogTypeNamesWhoseDetectorIndicesWouldBeRegisteredAreReserved() {
        for (String name : List.of("threat-intel", "threat-intel-feeds", "Threat-Intel_x")) {
            assertTrue(name, SecurityAnalyticsPlugin.logTypeIndicesMatchSystemIndices(name));
        }
        for (String name : List.of("windows", "threat", "threat_intel", "log-types", "detectors", "correlation-rules")) {
            assertFalse(name, SecurityAnalyticsPlugin.logTypeIndicesMatchSystemIndices(name));
        }
    }

    private boolean isRegistered(String index) {
        return descriptors.stream().anyMatch(descriptor -> descriptor.matchesIndexPattern(index));
    }
}
