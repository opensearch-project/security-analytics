package org.opensearch.securityanalytics.ruleengine.provider;

import java.util.List;

public interface RuleProvider {
    List<RuleData> getRuleData();
}
