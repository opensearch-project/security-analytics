/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.config.monitors;

import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;


public class DetectorMonitorConfig {
    public static final String OPENSEARCH_DEFAULT_RULE_INDEX = ".opensearch-sap-detectors-queries-default";
    public static final String OPENSEARCH_DEFAULT_ALERT_INDEX = ".opensearch-sap-alerts-default";
    public static final String OPENSEARCH_DEFAULT_FINDINGS_INDEX = ".opensearch-sap-findings-default";
    private static Map<String, MonitorConfig> ruleIndexByDetectorTypeMap;

    static {
        ruleIndexByDetectorTypeMap = new HashMap<>();
        Arrays.stream(Detector.DetectorType.values()).forEach(
                detectorType -> {
                    try {
                        String ruleIndex = String.format(
                                Locale.getDefault(), ".opensearch-sap-detectors-queries-%s", detectorType.getDetectorType());
                        String alertIndex = String.format(
                                Locale.getDefault(), ".opensearch-sap-alerts-%s", detectorType.getDetectorType());
                        String findingIndex = String.format(
                                Locale.getDefault(), ".opensearch-sap-findings-%s", detectorType.getDetectorType());
                        ;
                        MonitorConfig monitor = new MonitorConfig(alertIndex, findingIndex, ruleIndex);
                        ruleIndexByDetectorTypeMap.put(detectorType.getDetectorType(), monitor);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    public static String getRuleIndex(String detectorType) throws IOException {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getRuleIndex() :
                OPENSEARCH_DEFAULT_RULE_INDEX;
    }

    public static String getAlertIndex(String detectorType) throws IOException {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getAlertIndex() :
                OPENSEARCH_DEFAULT_ALERT_INDEX;
    }

    public static String getFindingsIndex(String detectorType) throws IOException {
        return ruleIndexByDetectorTypeMap.containsKey(detectorType) ?
                ruleIndexByDetectorTypeMap.get(detectorType).getFindingIndex() :
                OPENSEARCH_DEFAULT_FINDINGS_INDEX;
    }

    public static Map<String, Map<String, String>> getRuleIndexMappingsByType(String detectorType) {
        HashMap<String, String> properties = new HashMap<>();
        properties.put("analyzer", "rule_analyzer");
        HashMap<String, Map<String, String>> fieldMappingProperties = new HashMap<>();
        fieldMappingProperties.put("text", properties);
        return fieldMappingProperties;
    }

    private static class MonitorConfig {
        private final String alertIndex;
        private final String findingIndex;
        private final String ruleIndex;

        private MonitorConfig(String alertIndex, String findingIndex, String ruleIndex) {
            this.alertIndex = alertIndex;
            this.findingIndex = findingIndex;
            this.ruleIndex = ruleIndex;
        }

        public String getAlertIndex() {
            return alertIndex;
        }

        public String getFindingIndex() {
            return findingIndex;
        }

        public String getRuleIndex() {
            return ruleIndex;
        }
    }

}

