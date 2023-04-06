package org.opensearch.securityanalytics.rules.externalsourcing;

import java.util.List;
import java.util.Optional;

public class ExternalRuleSourcerManager {

    private List<ExternalRuleSourcer> externalRuleSourcers;


    public ExternalRuleSourcerManager(List<ExternalRuleSourcer> externalRuleSourcers) {
        this.externalRuleSourcers = externalRuleSourcers;
    }

    public ExternalRuleSourcer getSourcerById(String id) {
        Optional<ExternalRuleSourcer> opt =
                externalRuleSourcers.stream().filter(e -> e.getId().equals(id)).findFirst();
        if (opt.isPresent()) {
            return opt.get();
        } else {
            return null;
        }
    }
}
