/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.model;

import org.opensearch.securityanalytics.ruleengine.rules.Rule;

import java.util.ArrayList;
import java.util.List;

public class Match {
    private final DataType datum;
    private final List<Rule> rules;

    public Match(final DataType datum) {
        this.datum = datum;
        this.rules = new ArrayList<>();
    }

    public void addRule(final Rule rule) {
        rules.add(rule);
    }
}
