/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.Locale;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.securityanalytics.model.Detector;


import static org.opensearch.action.ValidateActions.addValidationError;

public class GetFindingsRequest extends ActionRequest {

    private String logType;
    private String detectorId;
    private Table table;
    private String severity;
    private String detectionType;

    public static final String DETECTOR_ID = "detector_id";

    public GetFindingsRequest(String detectorId) {
        super();
        this.detectorId = detectorId;
    }
    public GetFindingsRequest(StreamInput sin) throws IOException {
        this(
            sin.readOptionalString(),
            sin.readOptionalString(),
            Table.readFrom(sin), sin.readOptionalString(), sin.readOptionalString()
        );
    }

    public GetFindingsRequest(String detectorId, String logType, Table table, String severity, String detectionType) {
        this.detectorId = detectorId;
        this.logType = logType;
        this.table = table;
        this.severity = severity;
        this.detectionType = detectionType;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (detectorId != null && detectorId.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(),
                            "detector_id is missing"),
                    validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(detectorId);
        out.writeOptionalString(logType);
        table.writeTo(out);
        out.writeOptionalString(severity);
        out.writeOptionalString(detectionType);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDetectionType() {
        return detectionType;
    }

    public String getLogType() {
        return logType;
    }

    public Table getTable() {
        return table;
    }
}