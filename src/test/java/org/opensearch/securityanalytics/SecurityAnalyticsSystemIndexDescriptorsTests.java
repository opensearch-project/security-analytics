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

    public void testEveryIndexThePluginOwnsIsRegistered() {
        List<String> owned = List.of(
                Detector.DETECTORS_INDEX,
                CorrelationRule.CORRELATION_RULE_INDEX,
                CorrelationIndices.CORRELATION_ALERT_INDEX,
                LogTypeService.LOG_TYPE_INDEX,
                Rule.PRE_PACKAGED_RULES_INDEX,
                Rule.CUSTOM_RULES_INDEX,
                STIX2IOCFeedStore.getNewActiveIndex("Config-Id"),
                ".opensearch-sap-ioc-findings",
                ".opensearch-sap-ioc-findings-history-2026.11.19-1",
                ".opensearch-sap-threat-intel",
                ".opensearch-sap-threat-intel-feodo-1700000000000",
                ".opensearch-sap-threat-intel-alerts",
                ".opensearch-sap-threat-intel-alerts-history-2026.11.19-1",
                CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX,
                ".opensearch-sap-correlation-history-2026.11.19-1",
                CorrelationIndices.CORRELATION_METADATA_INDEX,
                SecurityAnalyticsPlugin.JOB_INDEX_NAME
        );
        for (String index : owned) {
            assertTrue(index + " is registered", isRegistered(index));
        }
    }

    public void testTheIndicesTheAlertingPluginWritesAreNotRegistered() {
        // A detector's monitors write these through the alerting plugin, which must keep reaching them.
        List<String> alertingWritten = List.of(
                DetectorMonitorConfig.getAlertsIndex("windows"),
                DetectorMonitorConfig.getAlertsHistoryIndex("windows"),
                DetectorMonitorConfig.getFindingsIndex("windows"),
                DetectorMonitorConfig.getRuleIndex("windows"),
                DetectorMonitorConfig.getRuleIndexOptimized("windows")
        );
        for (String index : alertingWritten) {
            assertFalse(index + " is not registered", isRegistered(index));
        }
    }

    private boolean isRegistered(String index) {
        return descriptors.stream().anyMatch(descriptor -> descriptor.matchesIndexPattern(index));
    }
}
