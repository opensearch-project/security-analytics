/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class DeleteDetectorRequest extends ActionRequest {

    private String detectorId;
    private WriteRequest.RefreshPolicy refreshPolicy;

    public DeleteDetectorRequest(String detectorId, WriteRequest.RefreshPolicy refreshPolicy) {
        super();
        this.detectorId = detectorId;
        this.refreshPolicy = refreshPolicy;
    }

    public DeleteDetectorRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        refreshPolicy.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}