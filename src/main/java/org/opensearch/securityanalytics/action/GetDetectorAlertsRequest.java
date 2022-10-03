package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.model.Table;

import java.io.IOException;

public class GetDetectorAlertsRequest extends ActionRequest {

    private final String detectorId;

    private final String alertState;

    private final String severityLevel;
    private final Table table;

    public GetDetectorAlertsRequest(String detectorId, String alertState, String severityLevel, Table table) {
        super();
        this.detectorId = detectorId;
        this.alertState = alertState;
        this.severityLevel = severityLevel;
        this.table = table;
    }

    public GetDetectorAlertsRequest(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString(), sin.readString(), Table.readFrom(sin)
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        out.writeString(alertState);
        out.writeString(severityLevel);
        table.writeTo(out);
    }

    public String getAlertState() {
        return alertState;
    }

    public String getSeverityLevel() {
        return severityLevel;
    }

    public Table getTable() {
        return table;
    }

    public String getDetectorId() {
        return detectorId;
    }

}