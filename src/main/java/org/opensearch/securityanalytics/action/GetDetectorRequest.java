/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class GetDetectorRequest extends ActionRequest {

    private String detectorId;
    public static final String DETECTOR_ID = "detectorID";

    public GetDetectorRequest() {
        super();
        this.detectorId = detectorId;
    }

    public GetDetectorRequest(String detectorId) {
        super();
        this.detectorId = detectorId;
    }
    public GetDetectorRequest(StreamInput sin) throws IOException {
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
        {
            out.writeString(detectorId);
        }
    }

    public static GetDetectorRequest parse(XContentParser xcp) throws IOException {
        String detectorId = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case DETECTOR_ID:
                    detectorId = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new GetDetectorRequest(detectorId);
    }

    public String getDetectorId() {
        return detectorId;
    }

}