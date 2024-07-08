package org.opensearch.securityanalytics.threatIntel.action.monitor.request;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.time.Instant;

public class GetThreatIntelAlertsRequest extends ActionRequest {

    private final String monitorId;
    private final Table table;
    private final String severityLevel;
    private final String alertState;
    private final Instant startTime;
    private final Instant endTime;

    public GetThreatIntelAlertsRequest(
            String monitorId,
            Table table,
            String severityLevel,
            String alertState,
            Instant startTime,
            Instant endTime
    ) {
        super();
        this.monitorId = monitorId;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
        this.startTime = startTime;
        this.endTime = endTime;
    }

    public GetThreatIntelAlertsRequest(
            Table table,
            String severityLevel,
            String alertState,
            Instant startTime,
            Instant endTime
    ) {
        super();
        this.monitorId = null;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
        this.startTime = startTime;
        this.endTime = endTime;
    }

    public GetThreatIntelAlertsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                Table.readFrom(sin),
                sin.readString(),
                sin.readString(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(monitorId);
        table.writeTo(out);
        out.writeString(severityLevel);
        out.writeString(alertState);
        out.writeOptionalInstant(startTime);
        out.writeOptionalInstant(endTime);
    }

    public String getmonitorId() {
        return monitorId;
    }

    public Table getTable() {
        return table;
    }

    public String getSeverityLevel() {
        return severityLevel;
    }

    public String getAlertState() {
        return alertState;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }


}

