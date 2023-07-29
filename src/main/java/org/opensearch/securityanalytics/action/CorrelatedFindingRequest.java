/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;

public class CorrelatedFindingRequest extends ActionRequest {

    private String detectorType;

    private String findingId;

    private long timeWindow;

    private int noOfNearbyFindings;

    public CorrelatedFindingRequest(String findingId, String detectorType, long timeWindow, int noOfNearbyFindings) {
        super();
        this.findingId = findingId;
        this.detectorType = detectorType;
        this.timeWindow = timeWindow;
        this.noOfNearbyFindings = noOfNearbyFindings;
    }

    public CorrelatedFindingRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readLong(),
                sin.readInt()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(findingId);
        out.writeString(detectorType);
        out.writeLong(timeWindow);
        out.writeInt(noOfNearbyFindings);
    }

    public String getFindingId() {
        return findingId;
    }

    public String getDetectorType() {
        return detectorType;
    }

    public long getTimeWindow() {
        return timeWindow;
    }

    public int getNoOfNearbyFindings() {
        return noOfNearbyFindings;
    }
}