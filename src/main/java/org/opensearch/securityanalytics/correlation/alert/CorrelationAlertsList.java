/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert;

import org.opensearch.commons.alerting.model.ActionExecutionResult;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper class that holds list of correlation alerts and total number of alerts available.
 * Useful for pagination.
 */
public class CorrelationAlertsList {

    private final List<CorrelationAlert> correlationAlertList;
    private final Integer totalAlerts;

    public CorrelationAlertsList(List<CorrelationAlert> correlationAlertList, Integer totalAlerts) {
        this.correlationAlertList = correlationAlertList;
        this.totalAlerts = totalAlerts;
    }

    // logic will be moved to common-utils, once the parsing logic in common-utils is fixed
    public static CorrelationAlert parse(XContentParser xcp, String id, long version) throws IOException {
        // Parse additional CorrelationAlert-specific fields
        List<String> correlatedFindingIds = new ArrayList<>();
        String correlationRuleId = null;
        String correlationRuleName = null;
        User user = null;
        int schemaVersion = 0;
        String triggerName = null;
        Alert.State state = null;
        String errorMessage = null;
        String severity = null;
        List<ActionExecutionResult> actionExecutionResults = new ArrayList<>();
        Instant startTime = null;
        Instant endTime = null;
        Instant acknowledgedTime = null;

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case CorrelationAlertService.CORRELATED_FINDING_IDS:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        correlatedFindingIds.add(xcp.text());
                    }
                    break;
                case CorrelationAlertService.CORRELATION_RULE_ID:
                    correlationRuleId = xcp.text();
                    break;
                case CorrelationAlertService.CORRELATION_RULE_NAME:
                    correlationRuleName = xcp.text();
                    break;
                case CorrelationAlertService.USER_FIELD:
                    user = (xcp.currentToken() == XContentParser.Token.VALUE_NULL) ? null : User.parse(xcp);
                    break;
                case CorrelationAlertService.ALERT_ID_FIELD:
                    id = xcp.text();
                    break;
                case CorrelationAlertService.ALERT_VERSION_FIELD:
                    version = xcp.longValue();
                    break;
                case CorrelationAlertService.SCHEMA_VERSION_FIELD:
                    schemaVersion = xcp.intValue();
                    break;
                case CorrelationAlertService.TRIGGER_NAME_FIELD:
                    triggerName = xcp.text();
                    break;
                case CorrelationAlertService.STATE_FIELD:
                    state = Alert.State.valueOf(xcp.text());
                    break;
                case CorrelationAlertService.ERROR_MESSAGE_FIELD:
                    errorMessage = xcp.textOrNull();
                    break;
                case CorrelationAlertService.SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case CorrelationAlertService.ACTION_EXECUTION_RESULTS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        actionExecutionResults.add(ActionExecutionResult.parse(xcp));
                    }
                    break;
                case CorrelationAlertService.START_TIME_FIELD:
                    startTime = Instant.parse(xcp.text());
                    break;
                case CorrelationAlertService.END_TIME_FIELD:
                    endTime = Instant.parse(xcp.text());
                    break;
                case CorrelationAlertService.ACKNOWLEDGED_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        acknowledgedTime = null;
                    } else {
                        acknowledgedTime = Instant.parse(xcp.text());
                    }
                    break;
            }
        }

            // Create and return CorrelationAlert object
            return new CorrelationAlert(
                    correlatedFindingIds,
                    correlationRuleId,
                    correlationRuleName,
                    id,
                    version,
                    schemaVersion,
                    user,
                    triggerName,
                    state,
                    startTime,
                    endTime,
                    acknowledgedTime,
                    errorMessage,
                    severity,
                    actionExecutionResults
            );
    }

    public List<CorrelationAlert> getCorrelationAlertList() {
        return correlationAlertList;
    }

    public Integer getTotalAlerts() {
        return totalAlerts;
    }

}
