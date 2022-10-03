package org.opensearch.securityanalytics.action;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.commons.alerting.alerts.AlertError;
import org.opensearch.commons.alerting.model.ActionExecutionResult;
import org.opensearch.commons.alerting.model.AggregationResultBucket;
import org.opensearch.commons.alerting.model.Alert;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

public class AlertDto extends ToXContentObject implements Writeable {

    private final String monitorName;
    private final String triggerName;
    private final List<String> findingIds;
    private final List<String> relatedDocIds;
    private final Alert.State state;
    private final Instant startTime;
    private final Instant endTime;
    private final Instant lastNotificationTime;
    private final Instant acknowledgedTime;
    private final String errorMessage;
    private final List<AlertError> errorHistory;
    private final String severity;
    private final List<ActionExecutionResult> actionExecutionResults;
    private final AggregationResultBucket aggregationResultBucket;

    public AlertDto(Alert alert) {
        this.monitorName = alert.getMonitorName();
        this.triggerName = alert.getTriggerName();
        this.findingIds = alert.getFindingIds();
        this.relatedDocIds = alert.getRelatedDocIds();
        this.state = alert.getState();
        this.startTime = alert.getStartTime();
        this.endTime = alert.getEndTime();
        this.lastNotificationTime = alert.getEndTime();
        this.acknowledgedTime = alert.getAcknowledgedTime();
        this.errorMessage = alert.getErrorMessage();
        this.errorHistory = alert.getErrorHistory();
        this.severity = alert.getSeverity();
        this.actionExecutionResults = alert.getActionExecutionResults();
        this.aggregationResultBucket = alert.getAggregationResultBucket();
    }

    public AlertDto(StreamInput sin) {
        this.monitorName = sin.readString();
        this.triggerName = alert.getTriggerName();
        this.findingIds = alert.getFindingIds();
        this.relatedDocIds = alert.getRelatedDocIds();
        this.state = alert.getState();
        this.startTime = alert.getStartTime();
        this.endTime = alert.getEndTime();
        this.lastNotificationTime = alert.getEndTime();
        this.acknowledgedTime = alert.getAcknowledgedTime();
        this.errorMessage = alert.getErrorMessage();
        this.errorHistory = alert.getErrorHistory();
        this.severity = alert.getSeverity();
        this.actionExecutionResults = alert.getActionExecutionResults();
        this.aggregationResultBucket = alert.getAggregationResultBucket();
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {

    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        return null;
    }

    public String getMonitorName() {
        return monitorName;
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

    public AggregationResultBucket getAggregationResultBucket() {
        return aggregationResultBucket;
    }
}
