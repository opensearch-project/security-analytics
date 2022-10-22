/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.Locale;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.securityanalytics.model.Detector;


import static org.opensearch.action.ValidateActions.addValidationError;

public class GetAlertsRequest extends ActionRequest {

    private String detectorId;
    private Detector.DetectorType detectorType;
    private Table table;
    private String severityLevel;
    private String alertState;

    public static final String DETECTOR_ID = "detector_id";

    public GetAlertsRequest(
            String detectorId,
            Detector.DetectorType detectorType,
            Table table,
            String severityLevel,
            String alertState
    ) {
        super();
        this.detectorId = detectorId;
        this.detectorType = detectorType;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
    }
    public GetAlertsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                sin.readBoolean() ? sin.readEnum(Detector.DetectorType.class) : null,
                Table.readFrom(sin),
                sin.readString(),
                sin.readString()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if ((detectorId == null || detectorId.length() == 0) && detectorType == null) {
            validationException = addValidationError(String.format(Locale.getDefault(),
                            "At least one of detector type or detector id needs to be passed", DETECTOR_ID),
                    validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(detectorId);
        if (detectorType != null) {
            out.writeBoolean(true);
            out.writeEnum(detectorType);
        } else out.writeBoolean(false);
        table.writeTo(out);
        out.writeString(severityLevel);
        out.writeString(alertState);
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

    public Detector.DetectorType getDetectorType() {
        return detectorType;
    }
}
