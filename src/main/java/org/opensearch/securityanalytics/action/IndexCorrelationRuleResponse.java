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
import org.opensearch.securityanalytics.model.CorrelationRule;

public class IndexCorrelationRuleResponse extends ActionResponse implements ToXContentObject {

    public static final String _ID = "_id";
    public static final String _VERSION = "_version";

    private String id;

    private Long version;

    private RestStatus status;

    private CorrelationRule correlationRule;

    public IndexCorrelationRuleResponse(String id, Long version, RestStatus status, CorrelationRule correlationRule) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.correlationRule = correlationRule;
    }

    public IndexCorrelationRuleResponse(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong(), sin.readEnum(RestStatus.class), CorrelationRule.readFrom(sin));
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field(_ID, id).field(_VERSION, version);

        builder.field("rule", correlationRule);
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        correlationRule.writeTo(out);
    }

    public String getId() {
        return id;
    }

    public RestStatus getStatus() {
        return status;
    }
}
