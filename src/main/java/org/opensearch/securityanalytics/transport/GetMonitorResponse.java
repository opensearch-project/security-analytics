/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import java.io.IOException;

class GetMonitorResponse extends ActionResponse implements ToXContentObject {
    public String id;
    public Long version;
    public Long seqNo;
    public Long primaryTerm;
    public RestStatus status;
    // public Monitor monitor;

    public GetMonitorResponse(
            String id,
            Long version,
            Long seqNo,
            Long primaryTerm,
            RestStatus status
            // Monitor monitor
    ) {
        super();
        this.id = id;
        this.version = version;
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
        this.status = status;
        // this.monitor = monitor;
    }

    public GetMonitorResponse(StreamInput sin) throws IOException {
        this.id = sin.readString(); // id
        this.version = sin.readLong(); // version
        this.seqNo = sin.readLong(); // seqNo
        this.primaryTerm = sin.readLong(); // primaryTerm
        this.status = sin.readEnum(RestStatus.class);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeLong(seqNo);
        out.writeLong(primaryTerm);
        out.writeEnum(status);
//        if (monitor != null) {
//            out.writeBoolean(true);
//            monitor.writeTo(out);
//        } else {
//            out.writeBoolean(false);
//        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("id", id)
                .field("version", version)
                .field("seqNo", seqNo)
                .field("primaryTerm", primaryTerm);
        //        if (this.monitor != null)
        //            builder.field("monitor", this.monitor);

        return builder.endObject();
    }
}
