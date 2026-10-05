/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.evaluator;

import org.opensearch.securityanalytics.ruleengine.model.Match;

import java.util.List;

public interface RuleEvaluator<T> {
    /**
     * A method to evaluate the rules against a set of incoming data.
     *
     * @param data - the data to be evaluated against the rules
     * @return - A list of Matches for positive rule evaluations against the incoming data
     */
    List<Match> evaluate(List<T> data);
}
