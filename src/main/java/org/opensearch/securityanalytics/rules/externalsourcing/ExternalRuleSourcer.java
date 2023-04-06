package org.opensearch.securityanalytics.rules.externalsourcing;

import org.opensearch.action.ActionListener;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportResponse;

public interface ExternalRuleSourcer {

    void importRules(RuleImportOptions options, ActionListener<ExternalSourceRuleImportResponse> listener);

    String getId();
}