/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.evaluator;

import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.ruleengine.model.Match;

import java.util.List;

public class StatelessRuleEvaluator implements RuleEvaluator<DataType> {
    @Override
    public List<Match> evaluate(final List<DataType> data) {
        return null;
    }
}
