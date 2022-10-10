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


import static org.opensearch.action.ValidateActions.addValidationError;

public class GetFindingsRequest extends ActionRequest {

    private String detectorId;
    private Table table;

    public static final String DETECTOR_ID = "detectorId";

    public GetFindingsRequest(String detectorId) {
        super();
        this.detectorId = detectorId;
    }
    public GetFindingsRequest(StreamInput sin) throws IOException {
        this(
            sin.readString(),
            Table.readFrom(sin)
        );
    }

    public GetFindingsRequest(String detectorId, Table table) {
        this.detectorId = detectorId;
        this.table = table;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (detectorId == null || detectorId.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", DETECTOR_ID), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        table.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public Table getTable() {
        return table;
    }
}