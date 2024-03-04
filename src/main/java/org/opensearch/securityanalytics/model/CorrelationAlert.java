package org.opensearch.securityanalytics.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.commons.alerting.model.ActionExecutionResult;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

/**
 * Model for docs store in .opensearch-sap-correlation-alerts index.
 * Correlation alerts are created when a detector finding triggers correlation
 */
public class CorrelationAlert implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(CorrelationAlert.class);
    private static final String ID_FIELD = "id";
    private static final String START_TIME_FIELD = "start_time";
    private static final String ACKNOWLEDGED_TIME_FIELD = "acknowledged_time";
    private static final String LAST_NOTIFICATION_TIME_FIELD = "last_notification_time";
    private static final String END_TIME_FIELD = "end_time";
    private static final String ACTION_EXECUTION_RESULTS_FIELD = "action_execution_results";
    private static final String VERSION_FIELD = "version";
    private static final String SCHEMA_VERSION_FIELD = "schema_version";
    private static final String TRIGGER_ID_FIELD = "trigger_id";
    private static final String TRIGGER_NAME_FIELD = "trigger_name";
    private static final String ERROR_MESSAGE_FIELD = "error_message";
    private static final String CORRELATED_FINDING_IDS_FIELD = "correlated_finding_ids";
    private static final String CORRELATED_RULE_NAMES_FIELD = "correlated_rule_names";
    private static final String CORRELATION_RULE_IDS_FIELD = "correlation_ids";
    private static final String USER_FIELD = "user";
    private static final String SEVERITY_FIELD = "severity";
    private static final String STATE_FIELD = "state";
    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            CorrelationAlert.class,
            new ParseField(ID_FIELD),
            xcp -> parse(xcp, null, null)
    );

    private final String id;
    private final Instant startTime;
    private final Instant acknowledgedTime;
    private final Instant lastNotificationTime;
    private final Instant endTime;
    private final List<ActionExecutionResult> actionExecutionResults;
    private final Integer version;
    private final Integer schemaVersion;
    private final String triggerName;
    private final String triggerId;
    private final String errorMessage;
    private final List<String> correlatedFindingIds;
    private final List<String> correlationRuleNames;
    private final List<String> correlationIds;
    private final User user;
    private final String severity;
    private final Alert.State state;


    public String getId() {
        return id;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getAcknowledgedTime() {
        return acknowledgedTime;
    }

    public Instant getLastNotificationTime() {
        return lastNotificationTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public List<String> getCorrelationIds() {
        return correlationIds;
    }

    public List<ActionExecutionResult> getActionExecutionResults() {
        return actionExecutionResults;
    }

    public Integer getVersion() {
        return version;
    }

    public Integer getSchemaVersion() {
        return schemaVersion;
    }

    public String getTriggerName() {
        return triggerName;
    }

    public String getTriggerId() {
        return triggerId;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public List<String> getCorrelatedFindingIds() {
        return correlatedFindingIds;
    }

    public List<String> getCorrelationRuleNames() {
        return correlationRuleNames;
    }

    public User getUser() {
        return user;
    }

    public String getSeverity() {
        return severity;
    }

    public Alert.State getState() {
        return state;
    }

    public CorrelationAlert(String id, Instant startTime, Instant acknowledgedTime,
                            Instant lastNotificationTime, Instant endTime, List<String> correlationIds,
                            List<ActionExecutionResult> actionExecutionResults, Integer version, Integer schemaVersion,
                            String triggerName, String triggerId, String errorMessage,
                            List<String> correlatedFindingIds, List<String> correlationRuleNames, User user,
                            String severity, Alert.State state) {
        this.id = id;
        this.startTime = startTime;
        this.acknowledgedTime = acknowledgedTime;
        this.lastNotificationTime = lastNotificationTime;
        this.endTime = endTime;
        this.correlationIds = correlationIds;
        this.actionExecutionResults = actionExecutionResults;
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


    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeInstant(startTime);
        out.writeInstant(acknowledgedTime);
        out.writeInstant(lastNotificationTime);
        out.writeInstant(endTime);
        out.writeStringCollection(correlationIds);
        out.writeCollection(actionExecutionResults);
        out.writeInt(version);
        out.writeInt(schemaVersion);
        out.writeString(triggerName);
        out.writeString(triggerId);
        out.writeString(errorMessage);
        out.writeStringCollection(correlatedFindingIds);
        out.writeStringCollection(correlationRuleNames);
        out.writeBoolean(user != null);
        if (user != null) {
            user.writeTo(out);
        }
        out.writeString(severity);
        out.writeEnum(state);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params, true);
    }

    public XContentBuilder toXContentWithUser(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params, false);
    }

    private XContentBuilder createXContentBuilder(XContentBuilder builder, Params params, boolean secure) throws IOException {
        builder.startObject()
                .field(ID_FIELD, id)
                .field(START_TIME_FIELD, startTime)
                .field(ACKNOWLEDGED_TIME_FIELD, acknowledgedTime)
                .field(LAST_NOTIFICATION_TIME_FIELD, lastNotificationTime)
                .field(END_TIME_FIELD, endTime)
                .field(CORRELATED_FINDING_IDS_FIELD, correlatedFindingIds)
                .field(ACTION_EXECUTION_RESULTS_FIELD, actionExecutionResults)
                .field(VERSION_FIELD, version)
                .field(SCHEMA_VERSION_FIELD, schemaVersion)
                .field(TRIGGER_NAME_FIELD, triggerName)
                .field(TRIGGER_ID_FIELD, triggerId)
                .field(ERROR_MESSAGE_FIELD, errorMessage)
                .field(CORRELATION_RULE_IDS_FIELD, correlationIds)
                .field(CORRELATED_RULE_NAMES_FIELD, correlationRuleNames);
        if (!secure) {
            if (user == null) {
                builder.nullField(USER_FIELD);
            } else {
                builder.field(USER_FIELD, user);
            }
        }
        builder.field(SEVERITY_FIELD, severity);
        builder.field(STATE_FIELD, state);
        return builder;
    }
}
