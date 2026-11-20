/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.List;
import java.util.Locale;

import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.threatIntel.model.TIFJobParameter;

/**
 * The plugin's system indices. The custom rules, IOC, IOC finding and correlation history and metadata indices are not
 * registered: their APIs or the dashboards read them as the caller.
 */
public final class SecurityAnalyticsSystemIndices {

    /** The descriptors the plugin registers. */
    public static final List<SystemIndexDescriptor> DESCRIPTORS = List.of(
            // Also covers the threat intel feed indices and the threat intel alert indices, which share the prefix.
            new SystemIndexDescriptor(TIFJobParameter.THREAT_INTEL_DATA_INDEX_NAME_PREFIX + "*", "System indices used for threat intel data and alerts"),
            new SystemIndexDescriptor(CorrelationIndices.CORRELATION_ALERT_INDEX, "System index used for Correlation Alerts"),
            new SystemIndexDescriptor(Detector.DETECTORS_INDEX, "System index used for detectors"),
            new SystemIndexDescriptor(CorrelationRule.CORRELATION_RULE_INDEX, "System index used for correlation rules"),
            new SystemIndexDescriptor(LogTypeService.LOG_TYPE_INDEX, "System index used for log types"),
            new SystemIndexDescriptor(Rule.PRE_PACKAGED_RULES_INDEX, "System index used for pre-packaged rules"),
            new SystemIndexDescriptor(SecurityAnalyticsPlugin.JOB_INDEX_NAME, "System index used for threat intel jobs and source configs")
    );

    private SecurityAnalyticsSystemIndices() {}

    /**
     * Returns whether a log type name would put a detector's alerting indices inside a registered system index pattern.
     * The alerting plugin writes those indices as the detector's monitor, so they must stay outside every descriptor.
     *
     * @param logTypeName the log type name a detector would use
     * @return true when one of the log type's detector indices matches a descriptor
     */
    public static boolean logTypeIndicesMatchSystemIndices(String logTypeName) {
        String name = logTypeName.toLowerCase(Locale.ROOT);
        List<String> detectorIndices = List.of(
                DetectorMonitorConfig.getAlertsIndex(name),
                DetectorMonitorConfig.getAlertsHistoryIndex(name),
                DetectorMonitorConfig.getFindingsIndex(name),
                DetectorMonitorConfig.getRuleIndex(name),
                DetectorMonitorConfig.getRuleIndexOptimized(name)
        );
        return detectorIndices.stream().anyMatch(index -> DESCRIPTORS.stream().anyMatch(d -> d.matchesIndexPattern(index)));
    }
}
