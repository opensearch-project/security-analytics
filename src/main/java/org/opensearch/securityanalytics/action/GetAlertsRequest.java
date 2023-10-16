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

public class GetAlertsRequest extends ActionRequest {

    private String detectorId;
    private ArrayList<String> findingIds;
    private String logType;
    private Table table;
    private String severityLevel;
    private String alertState;

    public static final String DETECTOR_ID = "detector_id";


    // Updated the constructor to include findingIds
    public GetAlertsRequest(
            String detectorId,
            ArrayList<String> findingIds,
            String logType,
            Table table,
            String severityLevel,
            String alertState
    ) {
        super();
        this.detectorId = detectorId;
        this.findingIds = findingIds;
        this.logType = logType;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
    }
    
    // Added the read for findingIds param
    public GetAlertsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                sin.readOptionalList(),
                sin.readOptionalString(),
                Table.readFrom(sin),
                sin.readString(),
                sin.readString()
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

    // Added the writeTo for findingIds
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(detectorId);
        out.writeOptionalList(findingIds);
        out.writeOptionalString(logType);
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

    public String getLogType() {
        return logType;
    }

    // Getter Function for findingIds
    public ArrayList<String> getFindingIds() {
        return findingIds;
    }
}
