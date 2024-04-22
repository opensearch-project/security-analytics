package org.opensearch.securityanalytics.ruleengine.parser;

import org.opensearch.securityanalytics.ruleengine.provider.RuleData;
import org.opensearch.securityanalytics.ruleengine.rules.ParsedRules;

public interface RuleParser {
    /**
     * A method to parse the information of a RuleData object into the internal representation of a rule used for evaluation.
     *
     * @param ruleData - the information representing one or more rules to be parsed
     * @return - A ParsedRules object containing the internal representation of the rules that were parsed
     */
    ParsedRules parseRules(RuleData ruleData);
}
