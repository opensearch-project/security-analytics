/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.Locale;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.securityanalytics.model.Detector;


import static org.opensearch.action.ValidateActions.addValidationError;

public class GetAlertsRequest extends ActionRequest {

    private String detectorId;
    private String logType;
    private Table table;
    private String severityLevel;
    private String alertState;

    private Instant startTime;

    private Instant endTime;

    public static final String DETECTOR_ID = "detector_id";

    public GetAlertsRequest(
            String detectorId,
            String logType,
            Table table,
            String severityLevel,
            String alertState,
            Instant startTime,
            Instant endTime
    ) {
        super();
        this.detectorId = detectorId;
        this.logType = logType;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
        this.startTime = startTime;
        this.endTime = endTime;
    }
    public GetAlertsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
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
        ActionRequestValidationException validationException = null;
        if ((detectorId == null || detectorId.length() == 0) && logType == null) {
            validationException = addValidationError(String.format(Locale.getDefault(),
                            "At least one of detector type or detector id needs to be passed", DETECTOR_ID),
                    validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(detectorId);
        out.writeOptionalString(logType);
        table.writeTo(out);
        out.writeString(severityLevel);
        out.writeString(alertState);
        out.writeOptionalInstant(startTime);
        out.writeOptionalInstant(endTime);
    }

    public String getDetectorId() {
        return detectorId;
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

    public String getLogType() {
        return logType;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }
}
