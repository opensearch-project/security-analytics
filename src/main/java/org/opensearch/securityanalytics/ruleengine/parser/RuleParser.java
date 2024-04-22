package org.opensearch.securityanalytics.ruleengine.parser;

import org.opensearch.securityanalytics.ruleengine.rules.ParsedRules;

public interface RuleParser {
    ParsedRules parseRules();
}
