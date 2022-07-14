/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaDetectionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SigmaDetections {

    private Map<String, SigmaDetection> detections;

    private List<String> condition;

    private List<SigmaCondition> parsedCondition;

    public SigmaDetections(Map<String, SigmaDetection> detections, List<String> condition) throws SigmaDetectionError {
        this.detections = detections;
        this.condition = condition;

        if (this.detections.isEmpty()) {
            throw new SigmaDetectionError("No detections defined in Sigma rule");
        }

        this.parsedCondition = new ArrayList<>();
        for (String cond: this.condition) {
            this.parsedCondition.add(new SigmaCondition(cond, this));
        }
    }

    @SuppressWarnings("unchecked")
    protected static SigmaDetections fromDict(Map<String, Object> detectionMap) throws SigmaConditionError, SigmaDetectionError, SigmaModifierError, SigmaValueError, SigmaRegularExpressionError {
        List<String> conditionList = new ArrayList<>();
        if (detectionMap.containsKey("condition") && detectionMap.get("condition") instanceof List) {
            conditionList.addAll((List<String>) detectionMap.get("condition"));
        } else if (detectionMap.containsKey("condition")) {
            conditionList.add(detectionMap.get("condition").toString());
        } else {
            throw new SigmaConditionError("Sigma rule must contain at least one condition");
        }

        Map<String, SigmaDetection> detections = new HashMap<>();
        for (Map.Entry<String, Object> detection: detectionMap.entrySet()) {
            if (!"condition".equals(detection.getKey())) {
                detections.put(detection.getKey(), SigmaDetection.fromDefinition(detection.getValue()));
            }
        }

        return new SigmaDetections(detections, conditionList);
    }

    public Map<String, SigmaDetection> getDetections() {
        return detections;
    }

    public List<String> getCondition() {
        return condition;
    }

    public List<SigmaCondition> getParsedCondition() {
        return parsedCondition;
    }
}