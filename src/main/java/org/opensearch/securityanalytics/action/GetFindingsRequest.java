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


import static org.opensearch.action.ValidateActions.addValidationError;

public class GetFindingsRequest extends ActionRequest {

    private String detectorId;
    private Long version;
    public static final String DETECTOR_ID = "detectorID";

    public GetFindingsRequest(String detectorId) {
        super();
        this.detectorId = detectorId;
        this.version = version;
    }
    public GetFindingsRequest(StreamInput sin) throws IOException {
        this(sin.readString());
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
    }

    public String getDetectorId() {
        return detectorId;
    }
}