/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class DeleteCustomLogTypeResponse extends ActionResponse implements ToXContentObject {

    private String id;

    private Long version;

    private RestStatus status;

    public DeleteCustomLogTypeResponse(String id, Long version, RestStatus status) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
    }

    public DeleteCustomLogTypeResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readEnum(RestStatus.class)
        );
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, id)
                .field(_VERSION, version);
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
    }
}