/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

import java.io.IOException;

public class ListCorrelationsRequest extends ActionRequest {

    private Long startTimestamp;

    private Long endTimestamp;

    public ListCorrelationsRequest(Long startTimestamp, Long endTimestamp) {
        super();
        this.startTimestamp = startTimestamp;
        this.endTimestamp = endTimestamp;
    }

    public ListCorrelationsRequest(StreamInput sin) throws IOException {
        this(
                sin.readLong(),
                sin.readLong()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeLong(startTimestamp);
        out.writeLong(endTimestamp);
    }

    public Long getStartTimestamp() {
        return startTimestamp;
    }

    public Long getEndTimestamp() {
        return endTimestamp;
    }
}