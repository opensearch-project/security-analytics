/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class GetDetectorRequest extends ActionRequest {

    private String detectorId;
    private Long version;
    public static final String DETECTOR_ID = "detector_id";

    public GetDetectorRequest(String detectorId, Long version) {
        super();
        this.detectorId = detectorId;
        this.version = version;
    }
    public GetDetectorRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             sin.readLong());
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
        out.writeLong(version);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public Long getVersion() {
        return version;
    }
}