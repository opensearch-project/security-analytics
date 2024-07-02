/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class SADeleteTIFSourceConfigResponse extends ActionResponse implements ToXContentObject {
    private final String id;
    private final RestStatus status;

    public SADeleteTIFSourceConfigResponse(String id, RestStatus status) {
        super();
        this.id = id;
        this.status = status;
    }

    public SADeleteTIFSourceConfigResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readEnum(RestStatus.class) // status
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, id);
        return builder.endObject();
    }

    public String getId() {
        return id;
    }


    public RestStatus getStatus() {
        return status;
    }

}