/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.rules;

import java.util.List;

public class ParsedRules {
    private final List<StatelessRule> statelessRules;
    private final List<StatefulRule> statefulRules;

    public ParsedRules(final List<StatelessRule> statelessRules, final List<StatefulRule> statefulRules) {
        this.statelessRules = statelessRules;
        this.statefulRules = statefulRules;
    }

    public List<StatelessRule> getStatelessRules() {
        return statelessRules;
    }

    public List<StatefulRule> getStatefulRules() {
        return statefulRules;
    }
}
