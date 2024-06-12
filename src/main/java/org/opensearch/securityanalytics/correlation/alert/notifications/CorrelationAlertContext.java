/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert.notifications;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CorrelationAlertContext {

    private final List<String> correlatedFindingIds;
    private final String sourceFinding;
    private final String correlationRuleName;
    private final long timeWindow;
    public CorrelationAlertContext(List<String> correlatedFindingIds, String correlationRuleName, long timeWindow, String sourceFinding) {
        this.correlatedFindingIds = correlatedFindingIds;
        this.correlationRuleName = correlationRuleName;
        this.timeWindow = timeWindow;
        this.sourceFinding = sourceFinding;
    }

    /**
     * Mustache templates need special permissions to reflectively introspect field names. To avoid doing this we
     * translate the context to a Map of Strings to primitive types, which can be accessed without reflection.
     */
    public Map<String, Object> asTemplateArg() {
        Map<String, Object> templateArg = new HashMap<>();
        templateArg.put("correlatedFindingIds", correlatedFindingIds);
        templateArg.put("sourceFinding", sourceFinding);
        templateArg.put("correlationRuleName", correlationRuleName);
        templateArg.put("timeWindow", timeWindow);
        return templateArg;
    }

}