package org.opensearch.securityanalytics.correlation.alert.notifications;

import org.opensearch.securityanalytics.model.CorrelationRule;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class CorrelationAlertContext {

    private final CorrelationRule correlationRule;
    private final List<String> correlatedFindingIds;
    protected CorrelationAlertContext(CorrelationRule correlationRule, List<String> correlatedFindingIds) {
        this.correlationRule = correlationRule;
        this.correlatedFindingIds = correlatedFindingIds;
    }

    /**
     * Mustache templates need special permissions to reflectively introspect field names. To avoid doing this we
     * translate the context to a Map of Strings to primitive types, which can be accessed without reflection.
     */
    public Map<String, Object> asTemplateArg() {
        Map<String, Object> templateArg = new HashMap<>();
        templateArg.put("correlationRule", correlationRule);
        templateArg.put("correlatedFindingIds", correlatedFindingIds);
        return templateArg;
    }

    public CorrelationRule getCorrelationRule() {
        return correlationRule;
    }

    public List<String> getCorrelatedFindingIds() {
        return correlatedFindingIds;
    }
}