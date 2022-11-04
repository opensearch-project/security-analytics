/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.config.monitors;

import java.util.ArrayList;
import java.util.List;
import org.opensearch.securityanalytics.model.Detector;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;


public class DetectorMonitorConfig {

    public static final String OPENSEARCH_DEFAULT_RULE_INDEX = ".opensearch-sap-detectors-queries-default";
    public static final String OPENSEARCH_DEFAULT_ALERT_INDEX = ".opensearch-sap-alerts-default";
    public static final String OPENSEARCH_DEFAULT_ALERT_HISTORY_INDEX = ".opensearch-sap-alerts-history-default";
    public static final String OPENSEARCH_DEFAULT_ALERT_HISTORY_INDEX_PATTERN = "<.opensearch-sap-alerts-history-default-{now/d}-1>";
    public static final String OPENSEARCH_DEFAULT_FINDINGS_INDEX = ".opensearch-sap-findings-default";
    public static final String OPENSEARCH_DEFAULT_FINDINGS_INDEX_PATTERN = "<.opensearch-sap-findings-default-{now/d}-1>";

    private static Map<String, MonitorConfig> detectorTypeToIndicesMapping;

    static {
        detectorTypeToIndicesMapping = new HashMap<>();
        Arrays.stream(Detector.DetectorType.values()).forEach(
                detectorType -> {
                    String ruleIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-%s-detectors-queries", detectorType.getDetectorType());
                    String alertsIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-%s-alerts", detectorType.getDetectorType());
                    String alertsHistoryIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-%s-alerts-history", detectorType.getDetectorType());
                    String alertsHistoryIndexPattern = String.format(
                            Locale.getDefault(), "<.opensearch-sap-%s-alerts-history-{now/d}-1>", detectorType.getDetectorType());
                    String allAlertsIndicesPattern = String.format(
                            Locale.getDefault(), ".opensearch-sap-%s-alerts*", detectorType.getDetectorType());
                    String findingsIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-%s-findings", detectorType.getDetectorType());
                    String findingsIndexPattern = String.format(
                            Locale.getDefault(), "<.opensearch-sap-%s-findings-{now/d}-1>", detectorType.getDetectorType());

                    MonitorConfig monitor = new MonitorConfig(alertsIndex, alertsHistoryIndex, alertsHistoryIndexPattern, allAlertsIndicesPattern, findingsIndex, findingsIndexPattern, ruleIndex);
                    detectorTypeToIndicesMapping.put(detectorType.getDetectorType(), monitor);
                });
    }

    public static String getRuleIndex(String detectorType) {
        return detectorTypeToIndicesMapping.containsKey(detectorType) ?
                detectorTypeToIndicesMapping.get(detectorType).getRuleIndex() :
                OPENSEARCH_DEFAULT_RULE_INDEX;
    }

    public static String getAlertsIndex(String detectorType) {
        return detectorTypeToIndicesMapping.containsKey(detectorType) ?
                detectorTypeToIndicesMapping.get(detectorType).getAlertsIndex() :
                OPENSEARCH_DEFAULT_ALERT_INDEX;
    }

    public static String getAlertsHistoryIndex(String detectorType) {
        return detectorTypeToIndicesMapping.containsKey(detectorType) ?
                detectorTypeToIndicesMapping.get(detectorType).getAlertsHistoryIndex() :
                OPENSEARCH_DEFAULT_ALERT_HISTORY_INDEX;
    }

    public static String getAlertsHistoryIndexPattern(String detectorType) {
        return detectorTypeToIndicesMapping.containsKey(detectorType) ?
                detectorTypeToIndicesMapping.get(detectorType).getAlertsHistoryIndexPattern() :
                OPENSEARCH_DEFAULT_ALERT_HISTORY_INDEX_PATTERN;
    }

    public static String getAllAlertsIndicesPattern(String detectorType) {
        return detectorTypeToIndicesMapping.containsKey(detectorType) ?
                detectorTypeToIndicesMapping.get(detectorType).getAllAlertsIndicesPattern() :
                "*";
    }

    public static String getFindingsIndex(String detectorType) {
        return detectorTypeToIndicesMapping.containsKey(detectorType) ?
                detectorTypeToIndicesMapping.get(detectorType).getFindingsIndex() :
                OPENSEARCH_DEFAULT_FINDINGS_INDEX;
    }

    public static String getFindingsIndexPattern(String detectorType) {
        return detectorTypeToIndicesMapping.containsKey(detectorType) ?
                detectorTypeToIndicesMapping.get(detectorType).getFindingsIndexPattern() :
                OPENSEARCH_DEFAULT_FINDINGS_INDEX_PATTERN;
    }

    public static Map<String, Map<String, String>> getRuleIndexMappingsByType(String detectorType) {
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
        private final String ruleIndex;

        private MonitorConfig(
                String alertsIndex,
                String alertsHistoryIndex,
                String alertsHistoryIndexPattern,
                String allAlertsIndicesPattern,
                String findingsIndex,
                String findingsIndexPattern,
                String ruleIndex
        ) {
            this.alertsIndex = alertsIndex;
            this.alertsHistoryIndex = alertsHistoryIndex;
            this.alertsHistoryIndexPattern = alertsHistoryIndexPattern;
            this.allAlertsIndicesPattern = allAlertsIndicesPattern;
            this.findingIndex = findingsIndex;
            this.findingsIndexPattern = findingsIndexPattern;
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

        public String getRuleIndex() {
            return ruleIndex;
        }
    }

}

