/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.config.monitors;

import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;
import org.opensearch.common.inject.Inject;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Detector;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.opensearch.securityanalytics.model.LogType;


public class DetectorMonitorConfig {

    public static final String OPENSEARCH_SAP_RULE_INDEX_TEMPLATE = ".opensearch-sap-detectors-queries-index-template";

    public static String getRuleIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries", logType);
    }

    public static String getRuleIndexOptimized(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries-optimized-%s", logType, UUID.randomUUID());
    }

    public static String getAlertsIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-alerts", logType);
    }

    public static String getAlertsHistoryIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-alerts-history", logType);
    }

    public static String getAlertsHistoryIndexPattern(String logType) {
        return String.format(Locale.getDefault(), "<.opensearch-sap-%s-alerts-history-{now/d}-1>", logType);
    }

    public static String getAllAlertsIndicesPattern(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-alerts*", logType);
    }

    public static String getFindingsIndexPattern(String logType) {
        return String.format(Locale.getDefault(), "<.opensearch-sap-%s-findings-{now/d}-1>", logType);
    }

    public static String getFindingsIndex(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-findings", logType);
    }

    public static String getAllFindingsIndicesPattern(String logType) {
        return String.format(Locale.getDefault(), ".opensearch-sap-%s-findings*", logType);
    }

    public static Map<String, Map<String, String>> getRuleIndexMappingsByType() {
        HashMap<String, String> properties = new HashMap<>();
        properties.put("analyzer", "rule_analyzer");
        HashMap<String, Map<String, String>> fieldMappingProperties = new HashMap<>();
        fieldMappingProperties.put("text", properties);
        return fieldMappingProperties;
    }

    public static class MonitorConfig {
        private final String alertsIndex;
        private final String alertsHistoryIndex;
        private final String alertsHistoryIndexPattern;
        private final String allAlertsIndicesPattern;
        private final String findingIndex;
        private final String findingsIndexPattern;
        private final String allFindingsIndicesPattern;
        private final String ruleIndex;

        private MonitorConfig(
                String alertsIndex,
                String alertsHistoryIndex,
                String alertsHistoryIndexPattern,
                String allAlertsIndicesPattern,
                String findingsIndex,
                String findingsIndexPattern,
                String allFindingsIndicesPattern,
                String ruleIndex) {
            this.alertsIndex = alertsIndex;
            this.alertsHistoryIndex = alertsHistoryIndex;
            this.alertsHistoryIndexPattern = alertsHistoryIndexPattern;
            this.allAlertsIndicesPattern = allAlertsIndicesPattern;
            this.findingIndex = findingsIndex;
            this.findingsIndexPattern = findingsIndexPattern;
            this.allFindingsIndicesPattern = allFindingsIndicesPattern;
            this.ruleIndex = ruleIndex;
        }

        public String getAlertsIndex() {
            return alertsIndex;
        }

        public String getAlertsHistoryIndex() {
            return alertsHistoryIndex;
        }

        public String getAlertsHistoryIndexPattern() {
            return alertsHistoryIndexPattern;
        }

        public String getAllAlertsIndicesPattern() {
            return allAlertsIndicesPattern;
        }

        public String getFindingsIndex() {
            return findingIndex;
        }

        public String getFindingsIndexPattern() {
            return findingsIndexPattern;
        }

        public String getAllFindingsIndicesPattern() {
            return allFindingsIndicesPattern;
        }

        public String getRuleIndex() {
            return ruleIndex;
        }
    }

}
