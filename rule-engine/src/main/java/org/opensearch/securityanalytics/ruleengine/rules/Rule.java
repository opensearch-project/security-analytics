/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.rules;

import java.util.function.Predicate;

public abstract class Rule<T, U> {
    private final String id;
    private final Predicate<T> evaluationCondition;
    private final Predicate<U> ruleCondition;

    public Rule(final String id, final Predicate<T> evaluationCondition, final Predicate<U> ruleCondition) {
        this.id = id;
        this.evaluationCondition = evaluationCondition;
        this.ruleCondition = ruleCondition;
    }
}
