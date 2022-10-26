/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.config.monitors;

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

    private static Map<String, MonitorConfig> ruleIndexByDetectorTypeMap;

    static {
        ruleIndexByDetectorTypeMap = new HashMap<>();
        Arrays.stream(Detector.DetectorType.values()).forEach(
                detectorType -> {
                    String ruleIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-detectors-queries-%s", detectorType.getDetectorType());
                    String alertsIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-alerts-%s", detectorType.getDetectorType());
                    String alertsHistoryIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-alerts-history-%s", detectorType.getDetectorType());
                    String alertsHistoryIndexPattern = String.format(
                            Locale.getDefault(), "<.opensearch-sap-alerts-history-%s-{now/d}-1>", detectorType.getDetectorType());
                    String findingsIndex = String.format(
                            Locale.getDefault(), ".opensearch-sap-findings-%s", detectorType.getDetectorType());
                    String findingsIndexPattern = String.format(
                            Locale.getDefault(), "<.opensearch-sap-findings-%s-{now/d}-1>", detectorType.getDetectorType());

                    MonitorConfig monitor = new MonitorConfig(alertsIndex, alertsHistoryIndex, alertsHistoryIndexPattern, findingsIndex, findingsIndexPattern, ruleIndex);
                    ruleIndexByDetectorTypeMap.put(detectorType.getDetectorType(), monitor);
                });
    }

    public static String getRuleIndex(String detectorType) {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getRuleIndex() :
                OPENSEARCH_DEFAULT_RULE_INDEX;
    }

    public static String getAlertsIndex(String detectorType) {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getAlertsIndex() :
                OPENSEARCH_DEFAULT_ALERT_INDEX;
    }

    public static String getAlertsHistoryIndex(String detectorType) {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getAlertsHistoryIndex() :
                OPENSEARCH_DEFAULT_ALERT_HISTORY_INDEX;
    }

    public static String getAlertsHistoryIndexPattern(String detectorType) {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getAlertsHistoryIndexPattern() :
                OPENSEARCH_DEFAULT_ALERT_HISTORY_INDEX_PATTERN;
    }

    public static String getFindingsIndex(String detectorType) {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getFindingsIndex() :
                OPENSEARCH_DEFAULT_FINDINGS_INDEX;
    }

    public static String getFindingsIndexPattern(String detectorType) {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getFindingsIndexPattern() :
                OPENSEARCH_DEFAULT_FINDINGS_INDEX_PATTERN;
    }

    public static Map<String, Map<String, String>> getRuleIndexMappingsByType(String detectorType) {
        HashMap<String, String> properties = new HashMap<>();
        properties.put("analyzer", "rule_analyzer");
        HashMap<String, Map<String, String>> fieldMappingProperties = new HashMap<>();
        fieldMappingProperties.put("text", properties);
        return fieldMappingProperties;
    }

    private static class MonitorConfig {
        private final String alertsIndex;
        private final String alertsHistoryIndex;
        private final String alertsHistoryIndexPattern;
        private final String findingIndex;
        private final String findingsIndexPattern;
        private final String ruleIndex;

        private MonitorConfig(
                String alertsIndex,
                String alertsHistoryIndex,
                String alertsHistoryIndexPattern,
                String findingsIndex,
                String findingsIndexPattern,
                String ruleIndex
        ) {
            this.alertsIndex = alertsIndex;
            this.alertsHistoryIndex = alertsHistoryIndex;
            this.alertsHistoryIndexPattern = alertsHistoryIndexPattern;
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

