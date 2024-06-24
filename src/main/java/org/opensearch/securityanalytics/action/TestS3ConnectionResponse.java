/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

public class TestS3ConnectionResponse extends ActionResponse implements ToXContentObject {
    public static final String STATUS_FIELD = "status";
    public static final String ERROR_FIELD = "error";

    private RestStatus status;
    private String error;

    public TestS3ConnectionResponse(RestStatus status, String error) {
        super();
        this.status = status;
        this.error = error;
    }

    public TestS3ConnectionResponse(StreamInput sin) throws IOException {
        this(sin.readEnum(RestStatus.class), sin.readOptionalString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(status);
        out.writeOptionalString(error);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(STATUS_FIELD, status)
                .field(ERROR_FIELD, error)
                .endObject();
    }

    public RestStatus getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }
}
