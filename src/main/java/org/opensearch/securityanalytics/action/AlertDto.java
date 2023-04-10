/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.lucene.uid.Versions;
import org.opensearch.commons.alerting.alerts.AlertError;
import org.opensearch.commons.alerting.model.ActionExecutionResult;
import org.opensearch.commons.alerting.model.AggregationResultBucket;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class AlertDto implements ToXContentObject, Writeable {

    private static final int NO_SCHEMA_VERSION = 0;
    private static final String DETECTOR_ID_FIELD = "detector_id";
    private static final String ALERT_ID_FIELD = "id";
    private static final String SCHEMA_VERSION_FIELD = "schema_version";
    private static final String ALERT_VERSION_FIELD = "version";
    private static final String TRIGGER_ID_FIELD = "trigger_id";
    private static final String TRIGGER_NAME_FIELD = "trigger_name";
    private static final String FINDING_IDS = "finding_ids";
    private static final String RELATED_DOC_IDS = "related_doc_ids";
    private static final String STATE_FIELD = "state";
    private static final String START_TIME_FIELD = "start_time";
    private static final String LAST_NOTIFICATION_TIME_FIELD = "last_notification_time";
    private static final String END_TIME_FIELD = "end_time";
    private static final String ACKNOWLEDGED_TIME_FIELD = "acknowledged_time";
    private static final String ERROR_MESSAGE_FIELD = "error_message";
    private static final String ALERT_HISTORY_FIELD = "alert_history";
    private static final String SEVERITY_FIELD = "severity";
    private static final String ACTION_EXECUTION_RESULTS_FIELD = "action_execution_results";
    private static final String NO_ID = "";

    private String id;
    private Long version;
    private Integer schemaVersion;
    private String triggerId;
    private String triggerName;
    private List<String> findingIds;
    private List<String> relatedDocIds;
    private Alert.State state;
    private Instant startTime;
    private Instant endTime;
    private Instant lastNotificationTime;
    private Instant acknowledgedTime;
    private String errorMessage;
    private List<AlertError> errorHistory;
    private String severity;
    private List<ActionExecutionResult> actionExecutionResults;

    private String detectorId;

    public AlertDto(
            String detectorId,
            String id,
            Long version,
            Integer schemaVersion,
            String triggerId,
            String triggerName,
            List<String> findingIds,
            List<String> relatedDocIds,
            Alert.State state,
            Instant startTime,
            Instant endTime,
            Instant lastNotificationTime,
            Instant acknowledgedTime,
            String errorMessage,
            List<AlertError> errorHistory,
            String severity,
            List<ActionExecutionResult> actionExecutionResults,
            AggregationResultBucket aggregationResultBucket
    ) {
        this.detectorId = detectorId;
        this.id = id != null ? id : NO_ID;
        this.version = version != null ? version : Versions.NOT_FOUND;
        this.schemaVersion = schemaVersion != null ? schemaVersion : NO_SCHEMA_VERSION;
        this.triggerId = triggerId;
        this.triggerName = triggerName;
        this.findingIds = findingIds;
        this.relatedDocIds = relatedDocIds;
        this.state = state;
        this.startTime = startTime;
        this.endTime = endTime;
        this.lastNotificationTime = lastNotificationTime;
        this.acknowledgedTime = acknowledgedTime;
        this.errorMessage = errorMessage;
        this.errorHistory = errorHistory;
        this.severity = severity;
        this.actionExecutionResults = actionExecutionResults;
        this.aggregationResultBucket = aggregationResultBucket;
    }

    AggregationResultBucket aggregationResultBucket;

    public AlertDto(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readLong(),
                sin.readInt(),
                sin.readString(),
                sin.readString(),
                sin.readStringList(),
                sin.readStringList(),
                sin.readEnum(Alert.State.class),
                sin.readInstant(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant(),
                sin.readOptionalString(),
                sin.readList(AlertError::new),
                sin.readString(),
                sin.readList(ActionExecutionResult::new),
                sin.readBoolean() ? new AggregationResultBucket(sin) : null
        );
    }

    public static AlertDto readFrom(StreamInput sin) throws IOException {
        return new AlertDto(sin);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(DETECTOR_ID_FIELD, detectorId)
                .field(ALERT_ID_FIELD, id)
                .field(ALERT_VERSION_FIELD, version)
                .field(SCHEMA_VERSION_FIELD, schemaVersion)
                .field(TRIGGER_ID_FIELD, triggerId)
                .field(TRIGGER_NAME_FIELD, triggerName)
                .field(FINDING_IDS, findingIds)
                .field(RELATED_DOC_IDS, relatedDocIds)
                .field(STATE_FIELD, state)
                .field(ERROR_MESSAGE_FIELD, errorMessage)
                .field(ALERT_HISTORY_FIELD, errorHistory)
                .field(SEVERITY_FIELD, severity)
                .field(ACTION_EXECUTION_RESULTS_FIELD, actionExecutionResults);

        if (startTime != null) {
            builder.field(START_TIME_FIELD, startTime);
        } else {
            builder.nullField(START_TIME_FIELD);
        }
        if (lastNotificationTime != null) {
            builder.field(LAST_NOTIFICATION_TIME_FIELD, lastNotificationTime);
        } else {
            builder.nullField(LAST_NOTIFICATION_TIME_FIELD);
        }
        if (endTime != null) {
            builder.field(END_TIME_FIELD, endTime);
        } else {
            builder.nullField(END_TIME_FIELD);
        }
        if (acknowledgedTime != null) {
            builder.field(ACKNOWLEDGED_TIME_FIELD, acknowledgedTime);
        } else {
            builder.nullField(ACKNOWLEDGED_TIME_FIELD);
        }
        if (aggregationResultBucket != null) {
            aggregationResultBucket.innerXContent(builder);
        }
        builder.endObject();
        return builder;
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        out.writeString(id);
        out.writeLong(version);
        out.writeInt(schemaVersion);
        out.writeString(triggerId);
        out.writeString(triggerName);
        out.writeStringCollection(findingIds);
        out.writeStringCollection(relatedDocIds);
        out.writeEnum(state);
        out.writeInstant(startTime);
        out.writeOptionalInstant(endTime);
        out.writeOptionalInstant(lastNotificationTime);
        out.writeOptionalInstant(acknowledgedTime);
        out.writeOptionalString(errorMessage);
        out.writeCollection(errorHistory);
        out.writeString(severity);
        out.writeCollection(actionExecutionResults);
        if (aggregationResultBucket != null) {
            out.writeBoolean(true);
            aggregationResultBucket.writeTo(out);
        } else {
            out.writeBoolean(false);
        }
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public Integer getSchemaVersion() {
        return schemaVersion;
    }

    public String getTriggerId() {
        return triggerId;
    }

    public String getTriggerName() {
        return triggerName;
    }

    public List<String> getFindingIds() {
        return findingIds;
    }

    public List<String> getRelatedDocIds() {
        return relatedDocIds;
    }

    public Alert.State getState() {
        return state;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public Instant getLastNotificationTime() {
        return lastNotificationTime;
    }

    public Instant getAcknowledgedTime() {
        return acknowledgedTime;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public List<AlertError> getErrorHistory() {
        return errorHistory;
    }

    public String getSeverity() {
        return severity;
    }

    public List<ActionExecutionResult> getActionExecutionResults() {
        return actionExecutionResults;
    }

    public String getDetectorId() {
        return detectorId;
    }

    public AggregationResultBucket getAggregationResultBucket() {
        return aggregationResultBucket;
    }
}