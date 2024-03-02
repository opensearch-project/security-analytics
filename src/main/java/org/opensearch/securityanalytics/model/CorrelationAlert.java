package org.opensearch.securityanalytics.model;

import org.opensearch.commons.alerting.model.ActionExecutionResult;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.authuser.User;

import java.time.Instant;
import java.util.List;

/**
 * Model for docs store in .opensearch-sap-correlation-alerts index.
 * Correlation alerts are created when a detector finding triggers correlation
 */
public class CorrelationAlert {

    private final String id;
    private final Instant startTime;
    private final Instant acknowledgedTime;
    private final Instant lastNotificationTime;
    private final Instant endTime;
    private final String correlationId;
    private final List<ActionExecutionResult> actionExecutionResult;
    private final Integer version;
    private final Integer schemaVersion;
    private final String triggerName;
    private final String triggerId;
    private final String errorMessage;
    private final List<String> correlatedFindingIds;
    private final List<String> correlationRuleNames;
    private final User user;
    private final String severity;
    private final Alert.State state;


    public CorrelationAlert(String id, Instant startTime, Instant acknowledgedTime,
                            Instant lastNotificationTime, Instant endTime, String correlationId,
                            List<ActionExecutionResult> actionExecutionResult, Integer version, Integer schemaVersion,
                            String triggerName, String triggerId, String errorMessage,
                            List<String> correlatedFindingIds, List<String> correlationRuleNames, User user,
                            String severity, Alert.State state) {
        this.id = id;
        this.startTime = startTime;
        this.acknowledgedTime = acknowledgedTime;
        this.lastNotificationTime = lastNotificationTime;
        this.endTime = endTime;
        this.correlationId = correlationId;
        this.actionExecutionResult = actionExecutionResult;
        this.version = version;
        this.schemaVersion = schemaVersion;
        this.triggerName = triggerName;
        this.triggerId = triggerId;
        this.errorMessage = errorMessage;
        this.correlatedFindingIds = correlatedFindingIds;
        this.correlationRuleNames = correlationRuleNames;
        this.user = user;
        this.severity = severity;
        this.state = state;
    }


}
