package org.opensearch.securityanalytics.ruleengine.provider;

import org.opensearch.securityanalytics.ruleengine.model.DataType;

import java.util.Map;
import java.util.function.Predicate;

public class RuleData {
    private final String ruleAsString;
    private final Predicate<DataType> evaluationCondition;
    private final Map<String, Object> metadata;

    public RuleData(final String ruleAsString, final Predicate<DataType> evaluationCondition, final Map<String, Object> metadata) {
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

    public Map<String, Object> getMetadata() {
        return metadata;
    }
}
