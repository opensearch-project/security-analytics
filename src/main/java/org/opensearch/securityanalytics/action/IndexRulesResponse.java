/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.util.RestHandlerUtils;

import java.io.IOException;

public class IndexRulesResponse extends ActionResponse implements ToXContentObject {

    private Long ruleCount;

    private RestStatus status;

    public IndexRulesResponse(Long ruleCount, RestStatus status) {
        super();
        this.ruleCount = ruleCount;
        this.status = status;
    }

    public IndexRulesResponse(StreamInput sin) throws IOException {
        this(sin.readLong(),
             sin.readEnum(RestStatus.class));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeLong(ruleCount);
        out.writeEnum(status);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(RestHandlerUtils.RULE_COUNT, ruleCount)
                .endObject();
    }

    public Long getRuleCount() {
        return ruleCount;
    }

    public RestStatus getStatus() {
        return status;
    }
}