/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;

public class IndexDetectorRequest extends ActionRequest {

    private String detectorId;

    private WriteRequest.RefreshPolicy refreshPolicy;

    private RestRequest.Method method;

    private Detector detector;

    public IndexDetectorRequest(
            String detectorId,
            WriteRequest.RefreshPolicy refreshPolicy,
            RestRequest.Method method,
            Detector detector) {
        super();
        this.detectorId = detectorId;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.detector = detector;
    }

    public IndexDetectorRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             WriteRequest.RefreshPolicy.readFrom(sin),
             sin.readEnum(RestRequest.Method.class),
             Detector.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        refreshPolicy.writeTo(out);
        out.writeEnum(method);
        detector.writeTo(out);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public Detector getDetector() {
        return detector;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}