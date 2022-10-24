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

public class GetFindingsRequest extends ActionRequest {

    private Detector.DetectorType detectorType;
    private String detectorId;
    private Table table;

    public static final String DETECTOR_ID = "detector_id";

    public GetFindingsRequest(String detectorId) {
        super();
        this.detectorId = detectorId;
    }
    public GetFindingsRequest(StreamInput sin) throws IOException {
        this(
            sin.readOptionalString(),
            sin.readBoolean() ? sin.readEnum(Detector.DetectorType.class) : null,
            Table.readFrom(sin)
        );
    }

    public GetFindingsRequest(String detectorId, Detector.DetectorType detectorType, Table table) {
        this.detectorId = detectorId;
        this.detectorType = detectorType;
        this.table = table;
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
        } else {
            out.writeBoolean(false);
        }
        table.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public Detector.DetectorType getDetectorType() {
        return detectorType;
    }

    public Table getTable() {
        return table;
    }
}