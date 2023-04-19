/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.CorrelatedFinding;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class ListCorrelationsResponse extends ActionResponse implements ToXContentObject {

    private List<CorrelatedFinding> correlatedFindings;

    protected static final String FINDINGS = "findings";

    public ListCorrelationsResponse(List<CorrelatedFinding> correlatedFindings) {
        super();
        this.correlatedFindings = correlatedFindings;
    }

    public ListCorrelationsResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(CorrelatedFinding::new))
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(correlatedFindings);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(FINDINGS, correlatedFindings)
                .endObject();
        return builder;
    }
}