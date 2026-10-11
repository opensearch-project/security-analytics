/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.model.Detector;

/**
 * The parts of a detector needed to find the detector's alerts: its id, log type, monitors and the rule id to monitor
 * id mapping (which tells whether the detector has a chained findings monitor).
 * <p>
 * Searching the alerts of many detectors only needs these fields, so the detector search can be limited to
 * {@link #SOURCE_INCLUDES} and parsed with {@link #parse}, instead of fetching and parsing full detector documents.
 */
public final class DetectorMonitors {

    private static final String DETECTOR_FIELD = "detector";
    private static final String DETECTOR_TYPE_FIELD = Detector.DETECTOR_TYPE_FIELD;
    private static final String MONITOR_ID_FIELD = Detector.ALERTING_MONITOR_ID;
    private static final String RULE_ID_MONITOR_ID_FIELD = Detector.BUCKET_MONITOR_ID_RULE_ID;

    /** The detector config doc fields read by {@link #parse} */
    public static final String[] SOURCE_INCLUDES = new String[] {
            DETECTOR_FIELD + "." + DETECTOR_TYPE_FIELD,
            DETECTOR_FIELD + "." + MONITOR_ID_FIELD,
            DETECTOR_FIELD + "." + RULE_ID_MONITOR_ID_FIELD
    };

    private final String id;
    private final String detectorType;
    private final List<String> monitorIds;
    private final Map<String, String> ruleIdMonitorIdMap;

    public DetectorMonitors(String id, String detectorType, List<String> monitorIds, Map<String, String> ruleIdMonitorIdMap) {
        this.id = id;
        this.detectorType = detectorType;
        this.monitorIds = monitorIds != null ? monitorIds : List.of();
        this.ruleIdMonitorIdMap = ruleIdMonitorIdMap != null ? ruleIdMonitorIdMap : Map.of();
    }

    public static DetectorMonitors of(Detector detector) {
        return new DetectorMonitors(detector.getId(), detector.getDetectorType(), detector.getMonitorIds(), detector.getRuleIdMonitorIdMap());
    }

    /**
     * Parses a detector config doc ({@code {"detector": {...}}}), which may be limited to {@link #SOURCE_INCLUDES}.
     * Other fields are skipped.
     */
    public static DetectorMonitors parse(XContentParser xcp, String id) throws IOException {
        String detectorType = null;
        List<String> monitorIds = new ArrayList<>();
        Map<String, String> ruleIdMonitorIdMap = new HashMap<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.currentToken(), xcp);
            String topLevelField = xcp.currentName();
            xcp.nextToken();
            if (DETECTOR_FIELD.equals(topLevelField) == false || xcp.currentToken() != XContentParser.Token.START_OBJECT) {
                // e.g. all_shared_principals added by resource sharing
                xcp.skipChildren();
                continue;
            }
            while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                String fieldName = xcp.currentName();
                xcp.nextToken();
                switch (fieldName) {
                    case DETECTOR_TYPE_FIELD:
                        detectorType = xcp.text();
                        break;
                    case MONITOR_ID_FIELD:
                        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                        while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                            monitorIds.add(xcp.text());
                        }
                        break;
                    case RULE_ID_MONITOR_ID_FIELD:
                        if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
                            ruleIdMonitorIdMap = xcp.mapStrings();
                        }
                        break;
                    default:
                        xcp.skipChildren();
                }
            }
        }
        return new DetectorMonitors(id, detectorType, monitorIds, ruleIdMonitorIdMap);
    }

    public String getId() {
        return id;
    }

    public String getDetectorType() {
        return detectorType;
    }

    public List<String> getMonitorIds() {
        return monitorIds;
    }

    public Map<String, String> getRuleIdMonitorIdMap() {
        return ruleIdMonitorIdMap;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        DetectorMonitors that = (DetectorMonitors) o;
        return Objects.equals(id, that.id) && Objects.equals(detectorType, that.detectorType)
                && Objects.equals(monitorIds, that.monitorIds) && Objects.equals(ruleIdMonitorIdMap, that.ruleIdMonitorIdMap);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, detectorType, monitorIds, ruleIdMonitorIdMap);
    }

    @Override
    public String toString() {
        return "DetectorMonitors{id=" + id + ", detectorType=" + detectorType + ", monitorIds=" + monitorIds
                + ", ruleIdMonitorIdMap=" + ruleIdMonitorIdMap + "}";
    }
}
