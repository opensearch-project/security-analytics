package org.opensearch.securityanalytics.ruleengine.rules;

import org.opensearch.securityanalytics.ruleengine.model.Match;

import java.time.Duration;
import java.util.List;
import java.util.function.Predicate;

public class StatefulRule extends Rule<Match, List<Match>> {
    private final Duration timeframe;
    private final List<String> filterFields;

    public StatefulRule(final String id, final Predicate<Match> evaluationCondition,
                        final Predicate<List<Match>> ruleCondition, final Duration timeframe,
                        final List<String> filterFields) {
        super(id, evaluationCondition, ruleCondition);
        this.timeframe = timeframe;
        this.filterFields = filterFields;
    }
}
