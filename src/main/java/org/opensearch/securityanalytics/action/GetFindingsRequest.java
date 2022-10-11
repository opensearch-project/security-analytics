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

    private final String detectorId;

    private final Table table;

    private final Detector.DetectorType detectorType;
    public static final String DETECTOR_ID = "detectorId";

    public GetFindingsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                Table.readFrom(sin),
                sin.readBoolean() ? sin.readEnum(Detector.DetectorType.class) : null
        );
    }

    public GetFindingsRequest(String detectorId, Table table) {
        this.detectorId = detectorId;
        this.table = table;
        this.detectorType = null;
    }

    public GetFindingsRequest(String detectorId, Table table, Detector.DetectorType detectorType) {
        this.detectorId = detectorId;
        this.table = table;
        this.detectorType = detectorType;
    }

    public GetFindingsRequest(Detector.DetectorType detectorType, Table table) {
        this.detectorType = detectorType;
        this.table = table;
        this.detectorId = null;
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
        table.writeTo(out);
        if (detectorType != null) {
            out.writeBoolean(true);
            out.writeEnum(detectorType);
        } else out.writeBoolean(false);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public Table getTable() {
        return table;
    }

    public Detector.DetectorType getDetectorType() {
        return detectorType;
    }
}