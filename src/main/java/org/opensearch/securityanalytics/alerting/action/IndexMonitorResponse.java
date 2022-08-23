/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */


package org.opensearch.securityanalytics.alerting.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.alerting.model.Monitor;
import org.opensearch.securityanalytics.model2.ModelSerializer;

import java.io.IOException;

public class IndexMonitorResponse extends ActionResponse implements ToXContentObject {

    public static final String _ID = "_id";
    public static final String _VERSION = "_version";
    public static final String _SEQ_NO = "_seq_no";
    public static final String IF_SEQ_NO = "if_seq_no";
    public static final String _PRIMARY_TERM = "_primary_term";
    public static final String IF_PRIMARY_TERM = "if_primary_term";
    public static final String REFRESH = "refresh";

    public String id;
    public Long version;
    public Long seqNo;
    public Long primaryTerm;
    public RestStatus status;
    public Monitor monitor;

    public IndexMonitorResponse(final String id, final Long version, final Long seqNo, final Long primaryTerm, final RestStatus status, final Monitor monitor) {
        this.id = id;
        this.version = version;
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
        this.status = status;
        this.monitor = monitor;
    }


    public IndexMonitorResponse(final StreamInput input) throws IOException {
        this(input.readString(), input.readLong(), input.readLong(), input.readLong(), input.readEnum(RestStatus.class), ModelSerializer.read(input, Monitor.class));
    }

    @Override
    public void writeTo(final StreamOutput output) throws IOException {
        output.writeString(this.id);
        output.writeLong(this.version);
        output.writeLong(this.seqNo);
        output.writeLong(this.primaryTerm);
        output.writeEnum(this.status);
        ModelSerializer.write(output, this.monitor);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject()
                .field(_ID, this.id)
                .field(_VERSION, this.version)
                .field(_SEQ_NO, this.seqNo)
                .field(_PRIMARY_TERM, this.primaryTerm)
                .field("monitor", this.monitor)
                .endObject();
    }
}
