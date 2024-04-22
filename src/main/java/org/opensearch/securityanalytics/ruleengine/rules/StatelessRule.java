package org.opensearch.securityanalytics.ruleengine.rules;

import org.opensearch.securityanalytics.ruleengine.model.DataType;

import java.util.function.Predicate;

public class StatelessRule extends Rule<DataType, DataType> {
    private final boolean isStatefulCondition;

    public StatelessRule(final String id, final Predicate<DataType> evaluationCondition,
                         final Predicate<DataType> ruleCondition, final boolean isStatefulCondition) {
        super(id, evaluationCondition, ruleCondition);
        this.isStatefulCondition = isStatefulCondition;
    }
}
