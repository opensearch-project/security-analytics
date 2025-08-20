/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.provider;

import org.opensearch.securityanalytics.ruleengine.model.DataType;

import java.util.Map;
import java.util.function.Predicate;

public class RuleData {
    private final String ruleAsString;
    private final Predicate<DataType> evaluationCondition;
    private final Map<String, String> metadata;

    public RuleData(final String ruleAsString, final Predicate<DataType> evaluationCondition, final Map<String, String> metadata) {
        this.ruleAsString = ruleAsString;
        this.evaluationCondition = evaluationCondition;
        this.metadata = metadata;
    }

    public String getRuleAsString() {
        return ruleAsString;
    }

    public Predicate<DataType> getEvaluationCondition() {
        return evaluationCondition;
    }

    public Map<String, String> getMetadata() {
        return metadata;
    }
}
