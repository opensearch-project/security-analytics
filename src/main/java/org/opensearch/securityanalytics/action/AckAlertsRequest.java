/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class AckAlertsRequest extends ActionRequest {

    private final String detectorId;

    private final List<String> alertIds;

    public AckAlertsRequest(String detectorId, List<String> alertIds) {
        this.detectorId = detectorId;
        this.alertIds = alertIds;
    }

    public AckAlertsRequest(StreamInput in) throws IOException {
        detectorId = in.readString();
        alertIds = Collections.unmodifiableList(in.readStringList());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (detectorId == null) {
            validationException = ValidateActions.addValidationError("detector id is mandatory", validationException);
        } else if(alertIds == null || alertIds.isEmpty()) {
            validationException = ValidateActions.addValidationError("alert ids list cannot be empty", validationException);
        }
        return validationException;
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.detectorId);
        out.writeStringCollection(this.alertIds);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject()
                .field("detector_id", detectorId)
                .field("alert_ids", alertIds)
                .endObject();
    }

    public static AckAlertsRequest readFrom(StreamInput sin) throws IOException {
        return new AckAlertsRequest(sin);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public List<String> getAlertIds() {
        return alertIds;
    }
}