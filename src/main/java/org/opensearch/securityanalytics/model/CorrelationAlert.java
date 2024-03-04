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
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

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
    private static final String CORRELATION_RULE_IDS_FIELD = "correlation_rule_ids";
    private static final String USER_FIELD = "user";
    private static final String SEVERITY_FIELD = "severity";
    private static final String STATE_FIELD = "state";
    public static final String NO_ID = "";
    public static final Long NO_VERSION = 1L;
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
    private final Long version;
    private final Long schemaVersion;
    private final String triggerName;
    private final String triggerId;
    private final String errorMessage;
    private final List<String> correlatedFindingIds;
    private final List<String> correlationRuleNames;
    private final List<String> correlationIds;
    private final User user;
    private final String severity;
    private final Alert.State state;


    public CorrelationAlert(String id, Instant startTime, Instant acknowledgedTime,
                            Instant lastNotificationTime, Instant endTime, List<String> correlationIds,
                            List<ActionExecutionResult> actionExecutionResults, Long version, Long schemaVersion,
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
        out.writeOptionalInstant(acknowledgedTime);
        out.writeInstant(lastNotificationTime);
        out.writeOptionalInstant(endTime);
        out.writeStringCollection(correlationIds);
        out.writeCollection(actionExecutionResults);
        out.writeLong(version);
        out.writeLong(schemaVersion);
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

    public static CorrelationAlert parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }
        Instant startTime = null;
        Instant acknowledgedTime = null;
        Instant lastNotificationTime = null;
        Instant endTime = null;
        List<ActionExecutionResult> actionExecutionResults = new ArrayList<>();
        Long schemaVersion = NO_VERSION;
        String triggerName = "";
        String triggerId = "";
        String errorMessage = "";
        List<String> correlatedFindingIds = new ArrayList<>();
        List<String> correlationRuleNames = new ArrayList<>();
        List<String> correlationIds = new ArrayList<>();
        User user = null;
        String severity = "";
        Alert.State state = null;
        ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case ID_FIELD:
                    id = xcp.text();
                    break;
                case START_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        startTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        startTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        startTime = null;
                    }
                    break;
                case ACKNOWLEDGED_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        acknowledgedTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        acknowledgedTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        acknowledgedTime = null;
                    }
                    break;
                case LAST_NOTIFICATION_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        lastNotificationTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        lastNotificationTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        lastNotificationTime = null;
                    }
                    break;
                case END_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        endTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        endTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        endTime = null;
                    }
                    break;
                case ACTION_EXECUTION_RESULTS_FIELD:
                    ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        actionExecutionResults.add(ActionExecutionResult.parse(xcp));
                    }
                    break;
                case VERSION_FIELD:
                    version = xcp.longValue();
                    break;
                case SCHEMA_VERSION_FIELD:
                    schemaVersion = xcp.longValue();
                    break;
                case TRIGGER_ID_FIELD:
                    triggerId = xcp.text();
                    break;
                case TRIGGER_NAME_FIELD:
                    triggerName = xcp.text();
                    break;
                case ERROR_MESSAGE_FIELD:
                    errorMessage = xcp.text();
                    break;
                case CORRELATED_FINDING_IDS_FIELD:
                    ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String correlatedFindingId = xcp.text();
                        correlatedFindingIds.add(correlatedFindingId);
                    }
                    break;
                case CORRELATED_RULE_NAMES_FIELD:
                    ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String correlatedRuleName = xcp.text();
                        correlationRuleNames.add(correlatedRuleName);
                    }
                    break;
                case CORRELATION_RULE_IDS_FIELD:
                    ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String correlatedRuleName = xcp.text();
                        correlationIds.add(correlatedRuleName);
                    }
                    break;
                case USER_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        user = null;
                    } else {
                        user = User.parse(xcp);
                    }
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case STATE_FIELD:
                    state = Alert.State.valueOf(xcp.text());
                    break;
            }
        }
        return new CorrelationAlert(
                id,
                startTime,
                acknowledgedTime,
                lastNotificationTime,
                endTime,
                correlationIds,
                actionExecutionResults,
                version,
                schemaVersion,
                triggerName,
                triggerId,
                errorMessage,
                correlatedFindingIds,
                correlationRuleNames,
                user,
                severity,
                state
        );
    }

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

    public Long getVersion() {
        return version;
    }

    public Long getSchemaVersion() {
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
}
