package org.opensearch.securityanalytics.rules.externalsourcing;

import java.util.EnumSet;
import org.opensearch.action.support.IndicesOptions;

public interface ExternalRuleSourcer {

    void importRules(RuleImportOptions options);

}