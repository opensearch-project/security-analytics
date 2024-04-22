package org.opensearch.securityanalytics.ruleengine.evaluator;

import org.opensearch.securityanalytics.ruleengine.model.Match;

import java.util.List;

public interface RuleEvaluator<T> {
    List<Match> evaluate(List<T> data);
}
